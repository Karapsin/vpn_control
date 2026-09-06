package com.kardinal.vpncontrol.desktop

import com.sun.jna.*
import com.sun.jna.platform.mac.SystemB
import com.sun.jna.ptr.PointerByReference
import java.nio.file.Path

/** Darwin's Java provider lacks SecureDirectoryStream; use pinned native descriptors, never path fallback. */
internal class DesktopMacInstallJobBackend(
    private val verifyTrust: (Path, Stat) -> Unit = { _, stat -> require(stat.uid == 0 && stat.mode.toInt() and 0x12 == 0) },
) : DesktopInstallJobBackend {
    @Structure.FieldOrder("device", "mode", "links", "inode", "uid", "gid", "rdevice", "times",
        "size", "blocks", "blockSize", "flags", "generation", "spare", "reserved")
    class Stat : Structure() {
        @JvmField var device = 0
        @JvmField var mode: Short = 0
        @JvmField var links: Short = 0
        @JvmField var inode = 0L
        @JvmField var uid = 0
        @JvmField var gid = 0
        @JvmField var rdevice = 0
        @JvmField var times = LongArray(8)
        @JvmField var size = 0L
        @JvmField var blocks = 0L
        @JvmField var blockSize = 0
        @JvmField var flags = 0
        @JvmField var generation = 0
        @JvmField var spare = 0
        @JvmField var reserved = LongArray(2)
    }
    private interface Api : Library {
        fun open(path: String, flags: Int): Int
        // Darwin arm64 passes variadic arguments differently: mode must remain a real JNA vararg.
        fun openat(directory: Int, name: String, flags: Int, vararg mode: Any): Int
        fun mkdirat(directory: Int, name: String, mode: Int): Int
        fun fstat64(fd: Int, stat: Stat): Int
        fun fchown(fd: Int, uid: Int, gid: Int): Int
        fun fchmod(fd: Int, mode: Int): Int
        fun renameat(source: Int, sourceName: String, target: Int, targetName: String): Int
        fun unlinkat(directory: Int, name: String, flags: Int): Int
        fun pread(fd: Int, buffer: ByteArray, count: Long, offset: Long): Long
        fun pwrite(fd: Int, buffer: ByteArray, count: Long, offset: Long): Long
        fun ftruncate(fd: Int, length: Long): Int
        fun fsync(fd: Int): Int
        fun close(fd: Int): Int
        fun getpwnam_r(name: String, passwd: SystemB.Passwd, buffer: Pointer, size: Long, result: PointerByReference): Int
    }
    private val api: Api by lazy {
        require(System.getProperty("os.name").startsWith("Mac", true) && Native.POINTER_SIZE == 8)
        Native.load("System", Api::class.java)
    }
    private fun checked(result: Int): Int { check(result >= 0) { "Protected installer storage operation failed" }; return result }
    private fun stat(fd: Int): Stat = Stat().also { checked(api.fstat64(fd, it)) }
    private fun inspect(fd: Int, path: Path, directory: Boolean, cancellation: Boolean = false) {
        val metadata = stat(fd)
        require(metadata.mode.toInt() and 0xf000 == if (directory) 0x4000 else 0x8000)
        if (!cancellation) { verifyTrust(path, metadata); DesktopMacInstallJobAcl.requireAbsent(fd) }
        require(metadata.mode.toInt() and 0x12 == 0)
        if (!directory) require(metadata.links.toInt() == 1)
    }
    override fun openRoot(root: Path, create: Boolean): DesktopInstallJobBackend.Directory {
        require(root.isAbsolute && root == root.normalize() && root.nameCount > 0)
        val retained = mutableListOf<Int>()
        try {
            var absolute = root.root
            var fd = checked(api.open("/", DIRECTORY_FLAGS)).also { retained += it }
            inspect(fd, absolute, directory = true)
            root.forEachIndexed { index, name ->
                var created = false
                if (create && index == root.nameCount - 1) {
                    val result = api.mkdirat(fd, name.toString(), 0x1ed)
                    if (result != 0) require(Native.getLastError() == 17) // EEXIST; still inspect without following.
                    created = result == 0
                }
                fd = checked(api.openat(fd, name.toString(), DIRECTORY_FLAGS, 0)).also { retained += it }
                if (created) checked(api.fchmod(fd, 0x1ed)) // Do not inherit helper's restrictive umask.
                absolute = absolute.resolve(name)
                inspect(fd, absolute, directory = true)
            }
            return Directory(fd, absolute, retained)
        } catch (failure: Exception) { retained.asReversed().forEach { api.close(it) }; throw failure }
    }
    private inner class Directory(private val fd: Int, private val path: Path,
        private val retained: List<Int> = listOf(fd),
    ) : DesktopInstallJobBackend.Directory {
        private var closed = false
        private fun checkOpen() = check(!closed)
        override fun createJob(jobId: String): DesktopInstallJobBackend.Directory {
            checkOpen(); require(DesktopInstallJobNames.validJob(jobId))
            checked(api.mkdirat(fd, jobId, 0x1ed))
            val created = checked(api.openat(fd, jobId, DIRECTORY_FLAGS, 0))
            try { checked(api.fchmod(created, 0x1ed)) } finally { api.close(created) }
            return openJob(jobId)
        }
        override fun openJob(jobId: String): DesktopInstallJobBackend.Directory {
            checkOpen(); require(DesktopInstallJobNames.validJob(jobId))
            val child = checked(api.openat(fd, jobId, DIRECTORY_FLAGS, 0))
            try { inspect(child, path.resolve(jobId), true); return Directory(child, path.resolve(jobId)) }
            catch (failure: Exception) { api.close(child); throw failure }
        }
        override fun createFile(name: String, purpose: DesktopInstallJobBackend.Purpose,
            clientPrincipal: String?,
        ): DesktopInstallJobBackend.File {
            checkOpen(); DesktopInstallJobNames.requireCreate(name, purpose)
            val cancel = purpose == DesktopInstallJobBackend.Purpose.CANCEL
            require(cancel == (clientPrincipal != null))
            val file = checked(api.openat(fd, name, FILE_FLAGS or 2 or 0x200 or 0x800, if (cancel) 0x180 else 0x1a4))
            try {
                checked(api.fchmod(file, if (cancel) 0x180 else 0x1a4))
                if (clientPrincipal != null) {
                    require(clientPrincipal.isNotBlank() && clientPrincipal.length <= 256 && '\u0000' !in clientPrincipal)
                    Memory(65536).use { buffer ->
                        val passwd = SystemB.Passwd()
                        val result = PointerByReference()
                        require(api.getpwnam_r(clientPrincipal, passwd, buffer, buffer.size(), result) == 0 && result.value != null)
                        checked(api.fchown(file, passwd.pw_uid, -1))
                    }
                }
                inspect(file, path.resolve(name), false, cancel)
                return File(file, writable = true, cancellationOnly = false)
            } catch (failure: Exception) { api.close(file); throw failure }
        }
        override fun openFile(name: String, write: Boolean): DesktopInstallJobBackend.File {
            checkOpen(); DesktopInstallJobNames.requireReadable(name)
            require(!write || name == DesktopInstallJobNames.CANCEL)
            val file = checked(api.openat(fd, name, FILE_FLAGS or if (write) 2 else 0, 0))
            try {
                inspect(file, path.resolve(name), false, name == DesktopInstallJobNames.CANCEL)
                return File(file, write, write)
            } catch (failure: Exception) { api.close(file); throw failure }
        }
        override fun replaceFile(tempName: String, targetName: String) {
            checkOpen(); require(DesktopInstallJobNames.validTemp(tempName) && targetName == DesktopInstallJobNames.STATUS)
            val source = checked(api.openat(fd, tempName, FILE_FLAGS, 0))
            try { inspect(source, path.resolve(tempName), false) } finally { api.close(source) }
            val target = api.openat(fd, targetName, FILE_FLAGS, 0)
            if (target >= 0) {
                try { inspect(target, path.resolve(targetName), false) } finally { api.close(target) }
            } else require(Native.getLastError() == 2)
            checked(api.renameat(fd, tempName, fd, targetName))
            checked(api.fsync(fd))
        }
        override fun deleteFile(name: String) {
            checkOpen(); require(DesktopInstallJobNames.validTemp(name)); checked(api.unlinkat(fd, name, 0))
        }
        override fun close() {
            if (closed) return
            closed = true
            retained.asReversed().forEach { api.close(it) }
        }
    }
    private inner class File(private val fd: Int, private val writable: Boolean,
        private val cancellationOnly: Boolean,
    ) : DesktopInstallJobBackend.File {
        private var closed = false
        @Synchronized override fun readBounded(maxBytes: Int): ByteArray {
            check(!closed); require(maxBytes in 1..DesktopInstallJobReceipt.MAX_BYTES)
            val bytes = ByteArray(maxBytes + 1)
            var total = 0
            while (total < bytes.size) {
                val chunk = ByteArray(bytes.size - total)
                val read = api.pread(fd, chunk, chunk.size.toLong(), total.toLong())
                check(read >= 0 && read <= chunk.size)
                if (read == 0L) break
                chunk.copyInto(bytes, total, 0, read.toInt()); total += read.toInt()
            }
            require(total <= maxBytes && stat(fd).size <= maxBytes)
            return bytes.copyOf(total)
        }
        @Synchronized override fun writeExact(bytes: ByteArray) {
            check(!closed && writable); require(bytes.size in 1..DesktopInstallJobReceipt.MAX_BYTES)
            require(!cancellationOnly || bytes.contentEquals(byteArrayOf(1)))
            var total = 0
            while (total < bytes.size) {
                val chunk = bytes.copyOfRange(total, bytes.size)
                val written = api.pwrite(fd, chunk, chunk.size.toLong(), total.toLong())
                check(written > 0 && written <= chunk.size); total += written.toInt()
            }
            checked(api.ftruncate(fd, bytes.size.toLong())); checked(api.fsync(fd))
        }
        @Synchronized override fun close() { if (!closed) { closed = true; api.close(fd) } }
    }
    private companion object {
        const val FILE_FLAGS = 0x01000000 or 0x100 // CLOEXEC | NOFOLLOW
        const val DIRECTORY_FLAGS = FILE_FLAGS or 0x00100000
    }
}
