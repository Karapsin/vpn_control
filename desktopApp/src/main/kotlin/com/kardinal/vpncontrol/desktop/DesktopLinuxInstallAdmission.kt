package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import java.nio.file.Files
import java.nio.file.Path

/** Read-only whole-file BSD flock, matching util-linux flock in the protected worker. */
internal object DesktopLinuxInstallAdmission {
    fun enter(native: LinuxInstallAdmissionNative = JnaLinuxInstallAdmission(),
        allowPendingControl: Boolean = false, onPendingControl: () -> Unit = {}): AutoCloseable {
        val retained = mutableListOf<Int>()
        var closed = false
        fun release() {
            if (closed) return
            closed = true
            var failure: Throwable? = null
            retained.asReversed().forEach { fd -> runCatching { native.close(fd) }.onFailure { failure = failure ?: it } }
            retained.clear()
            failure?.let { throw it }
        }
        fun pin(fd: Int, directory: Boolean): Int {
            retained += fd
            verify(native.inspect(fd), directory)
            return fd
        }
        try {
            var directory = pin(native.openRoot(), true)
            for (name in listOf("var", "lib")) directory = pin(native.openDirectory(directory, name), true)
            // Existing pre-updater processes cannot hold a not-yet-created gate. After creating it,
            // the worker rejects all surviving installed images before entering the package manager.
            val product = native.openOptionalDirectory(directory, "vpn-control-install-jobs")
                ?: return AutoCloseable { release() }.also { release() }
            directory = pin(product, true)
            val gate = native.openOptionalGate(directory, "gate-linux")
                ?: return AutoCloseable { release() }.also { release() }
            pin(gate, false)
            check(native.lockSharedNonBlocking(gate)) { "BUSY" }
            val before = native.inspect(gate)
            verify(before, false)
            val bytes = native.readGate(gate)
            val after = native.inspect(gate)
            verify(after, false)
            check(before == after) { "Unstable installation gate" }
            require(bytes.size == 17 && bytes.indices.all { if (it == 8) bytes[it] in 0..1 else bytes[it] == 0.toByte() }) {
                "Malformed installation gate"
            }
            check(bytes[8] == 0.toByte() || allowPendingControl) { "BUSY" }
            if (bytes[8] == 1.toByte()) onPendingControl()
            return object : AutoCloseable { @Synchronized override fun close() = release() }
        } catch (failure: Throwable) {
            runCatching { release() }
            throw failure
        }
    }

    private fun verify(info: LinuxAdmissionInfo, directory: Boolean) {
        require(info.uid == 0L && info.mode and 0x12 == 0) { "Untrusted installation gate" }
        require(info.mode and 0xf000 == if (directory) 0x4000 else 0x8000) { "Wrong installation gate type" }
        require(info.links > 0 && (directory || (info.links == 1L && info.size == 17L))) { "Malformed installation gate" }
    }
}

internal data class LinuxAdmissionInfo(val uid: Long, val mode: Int, val links: Long, val size: Long, val device: Long, val inode: Long)

internal interface LinuxInstallAdmissionNative {
    fun openRoot(): Int
    fun openDirectory(parent: Int, name: String): Int
    fun openOptionalDirectory(parent: Int, name: String): Int?
    fun openOptionalGate(parent: Int, name: String): Int?
    fun inspect(fd: Int): LinuxAdmissionInfo
    fun lockSharedNonBlocking(fd: Int): Boolean
    fun readGate(fd: Int): ByteArray
    fun close(fd: Int)
}

/** No fcntl/FileChannel locks: those do not interoperate with the worker's Linux flock. */
internal class JnaLinuxInstallAdmission : LinuxInstallAdmissionNative {
    private interface LibC : Library {
        fun open(path: String, flags: Int): Int
        fun openat(parent: Int, path: String, flags: Int): Int
        fun flock(fd: Int, operation: Int): Int
        fun pread(fd: Int, buffer: Memory, count: Long, offset: Long): Long
        fun close(fd: Int): Int
    }
    private val abi = linuxAdmissionOpenFlags(System.getProperty("os.arch"))
    private val libc = Native.load("c", LibC::class.java)
    // Linux O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC. Never create/write a root gate.
    private val flags = abi.nonBlocking or abi.noFollow or abi.closeOnExec
    override fun openRoot() = checked(libc.open("/", flags or abi.directory))
    override fun openDirectory(parent: Int, name: String): Int = requireNotNull(openChild(parent, name, true, false))
    override fun openOptionalDirectory(parent: Int, name: String) = openChild(parent, name, true, true)
    override fun openOptionalGate(parent: Int, name: String) = openChild(parent, name, false, true)
    private fun openChild(parent: Int, name: String, directory: Boolean, optional: Boolean): Int? {
        require(name.isNotEmpty() && name != "." && name != ".." && '/' !in name && '\u0000' !in name)
        val fd = libc.openat(parent, name, flags or if (directory) abi.directory else 0)
        if (fd < 0 && optional && Native.getLastError() == 2) return null
        return checked(fd)
    }
    override fun inspect(fd: Int): LinuxAdmissionInfo {
        // The descriptor is already O_NOFOLLOW/O_NONBLOCK-opened. /proc resolves that retained
        // inode; this does not reopen a user path or depend on architecture-specific stat layouts.
        val attributes = Files.readAttributes(Path.of("/proc/self/fd/$fd"), "unix:uid,mode,nlink,size,dev,ino")
        fun number(name: String) = (attributes.getValue(name) as Number).toLong()
        return LinuxAdmissionInfo(number("uid"), number("mode").toInt(), number("nlink"), number("size"), number("dev"), number("ino"))
    }
    override fun lockSharedNonBlocking(fd: Int): Boolean {
        val result = libc.flock(fd, 1 or 4)
        if (result == 0) return true
        if (Native.getLastError() == 11) return false
        error("UNAVAILABLE")
    }
    override fun readGate(fd: Int): ByteArray = Memory(18).use { memory ->
        val count = libc.pread(fd, memory, 18, 0)
        check(count in 0..18) { "UNAVAILABLE" }
        memory.getByteArray(0, count.toInt())
    }
    override fun close(fd: Int) { check(libc.close(fd) == 0) { "UNAVAILABLE" } }
    private fun checked(fd: Int): Int { check(fd >= 0) { "UNAVAILABLE" }; return fd }
}

internal data class LinuxAdmissionOpenFlags(val directory: Int, val noFollow: Int,
    val nonBlocking: Int = 0x800, val closeOnExec: Int = 0x80000)

/** Kernel UAPI arch/arm64/asm/fcntl.h overrides the generic directory/no-follow bits. */
internal fun linuxAdmissionOpenFlags(architecture: String): LinuxAdmissionOpenFlags = when (architecture.lowercase(java.util.Locale.ROOT)) {
    "aarch64", "arm64" -> LinuxAdmissionOpenFlags(0x4000, 0x8000)
    "amd64", "x86_64" -> LinuxAdmissionOpenFlags(0x10000, 0x20000)
    else -> error("UNSUPPORTED")
}
