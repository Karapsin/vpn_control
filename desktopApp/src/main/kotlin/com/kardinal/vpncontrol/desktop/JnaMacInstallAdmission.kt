package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.platform.mac.SystemB
import com.sun.jna.ptr.PointerByReference
import java.nio.file.Path

/** Darwin-only descriptor IO; never uses Java path fallback or runs a shell. */
internal class JnaMacInstallAdmission : MacInstallAdmissionNative {
    @Structure.FieldOrder("name", "password", "gid", "members")
    class NativeGroup : Structure() {
        @JvmField var name: Pointer? = null
        @JvmField var password: Pointer? = null
        @JvmField var gid: Int = 0
        @JvmField var members: Pointer? = null
    }
    private interface Api : Library {
        fun getuid(): Int
        fun geteuid(): Int
        fun getpid(): Int
        fun open(path: String, flags: Int): Int
        fun openat(parent: Int, name: String, flags: Int, vararg mode: Any): Int
        fun fcntl(fd: Int, command: Int, vararg argument: Any): Int
        fun flock(fd: Int, operation: Int): Int
        fun pread(fd: Int, memory: Pointer, count: Long, offset: Long): Long
        fun close(fd: Int): Int
        fun getpwuid_r(uid: Int, passwd: SystemB.Passwd, buffer: Pointer, size: Long, result: PointerByReference): Int
        fun getgrnam_r(name: String, group: NativeGroup, buffer: Pointer, size: Long, result: PointerByReference): Int
        fun proc_pidpath(pid: Int, buffer: Pointer, size: Int): Int
    }
    private val api: Api by lazy {
        require(System.getProperty("os.name").startsWith("Mac", true) && Native.POINTER_SIZE == 8)
        Native.load("System", Api::class.java)
    }
    // Same Darwin inode64 ABI selection as DesktopMacTransferFile, including arm64.
    private val stat by lazy {
        val library = NativeLibrary.getInstance("System")
        runCatching { library.getFunction("fstat" + '$' + "INODE64") }.getOrElse { library.getFunction("fstat") }
    }
    override fun currentUid(): Long {
        val uid = api.getuid()
        require(uid == api.geteuid()) { "Unexpected process credentials" }
        return uid.toLong() and 0xffffffffL
    }
    override fun currentExecutable(): String = Memory(4096).use { memory ->
        val count = api.proc_pidpath(api.getpid(), memory, memory.size().toInt())
        check(count > 0 && count < memory.size()) { "Process executable unavailable" }
        memory.getString(0, "UTF-8")
    }
    override fun homeDirectory(): Path = Memory(65536).use { memory ->
        val passwd = SystemB.Passwd()
        val result = PointerByReference()
        check(api.getpwuid_r(currentUid().toInt(), passwd, memory, memory.size(), result) == 0 && result.value != null)
        requireNotNull(passwd.pw_dir).let { Path.of(it) }.also { require(it.isAbsolute && it == it.normalize()) }
    }
    override fun adminGroupId(): Long? = Memory(65536).use { memory ->
        val group = NativeGroup()
        val result = PointerByReference()
        if (api.getgrnam_r("admin", group, memory, memory.size(), result) != 0 || result.value == null) return@use null
        if (group.name?.getString(0, "UTF-8") != "admin") return@use null
        group.gid.toLong() and 0xffffffffL
    }
    override fun openRoot() = checked(api.open("/", DIRECTORY_FLAGS))
    override fun openChild(parent: Int, name: String, directory: Boolean, optional: Boolean): Int? {
        require(name.isNotEmpty() && name !in setOf(".", "..") && '/' !in name && '\u0000' !in name)
        val fd = api.openat(parent, name, if (directory) DIRECTORY_FLAGS else FILE_FLAGS, 0)
        if (fd < 0 && optional && Native.getLastError() == 2) return null
        return checked(fd)
    }
    override fun inspect(fd: Int): MacAdmissionInfo = Memory(144).use { memory ->
        check(stat.invokeInt(arrayOf(fd, memory)) == 0) { "Admission descriptor unavailable" }
        MacAdmissionInfo(memory.getInt(16).toLong() and 0xffffffffL, memory.getShort(4).toInt() and 0xffff,
            (memory.getShort(6).toInt() and 0xffff).toLong(), memory.getLong(96), memory.getInt(0).toLong(), memory.getLong(8),
            memory.getInt(20).toLong() and 0xffffffffL, DesktopMacAdmissionAcl.inspect(fd))
    }
    override fun canonicalPath(fd: Int): Path = Memory(1024).use { memory ->
        check(api.fcntl(fd, 50, memory) == 0) { "Admission path unavailable" } // F_GETPATH
        Path.of(memory.getString(0, "UTF-8"))
    }
    override fun lockShared(fd: Int) = lock(fd, 1)
    internal fun lockExclusive(fd: Int) = lock(fd, 2)
    private fun lock(fd: Int, kind: Int): Boolean {
        if (api.flock(fd, kind or 4) == 0) return true // LOCK_NB
        if (Native.getLastError() == 35) return false // Darwin EWOULDBLOCK
        error("UNAVAILABLE")
    }
    override fun readGate(fd: Int): ByteArray = Memory(18).use { memory ->
        val count = api.pread(fd, memory, memory.size(), 0)
        check(count in 0..18) { "Admission gate unavailable" }
        memory.getByteArray(0, count.toInt())
    }
    override fun close(fd: Int) { checked(api.close(fd)) }
    private fun checked(value: Int): Int { check(value >= 0) { "UNAVAILABLE" }; return value }
    private companion object {
        const val FILE_FLAGS = 0x01000000 or 0x100 or 0x4 // O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        const val DIRECTORY_FLAGS = FILE_FLAGS or 0x00100000
    }
}
