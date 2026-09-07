package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.UUID

internal fun requireMacTransferAcl(acl: MacAdmissionAcl, private: Boolean, directory: Boolean) {
    require(acl == MacAdmissionAcl.EMPTY || !private && directory && acl == MacAdmissionAcl.DENY_ONLY) { "Untrusted transfer ACL" }
}

/** Darwin's JDK does not provide SecureDirectoryStream. Use real descriptor-relative IO. */
internal object DesktopMacTransferFile {
    private interface Api : Library {
        fun geteuid(): Int
        fun open(path: String, flags: Int): Int
        fun openat(parent: Int, name: String, flags: Int, vararg mode: Any): Int
        fun mkdirat(parent: Int, name: String, mode: Int): Int
        fun unlinkat(parent: Int, name: String, flags: Int): Int
        fun renameatx_np(source: Int, sourceName: String, target: Int, targetName: String, flags: Int): Int
        fun close(fd: Int): Int
        fun fsync(fd: Int): Int
        fun pread(fd: Int, bytes: ByteArray, size: Long, offset: Long): Long
        fun pwrite(fd: Int, bytes: ByteArray, size: Long, offset: Long): Long
        fun ftruncate(fd: Int, size: Long): Int
    }
    private val api: Api by lazy { Native.load("System", Api::class.java) }
    // Darwin arm64 only has the inode64 ABI. Intel also exports the explicit
    // inode64 symbol. The fixed offsets below are Darwin's public struct stat64.
    private val statFunction by lazy {
        val library = NativeLibrary.getInstance("System")
        runCatching { library.getFunction("fstat" + '$' + "INODE64") }.getOrElse { library.getFunction("fstat") }
    }
    private data class Info(val device: Int, val inode: Long, val mode: Int, val uid: Int, val links: Int, val size: Long)
    private fun stat(fd: Int): Info = Memory(144).use { memory ->
        check(statFunction.invokeInt(arrayOf(fd, memory)) == 0) { "Transfer descriptor inspection failed" }
        Info(memory.getInt(0), memory.getLong(8), memory.getShort(4).toInt() and 0xffff,
            memory.getInt(16), memory.getShort(6).toInt() and 0xffff, memory.getLong(96))
    }
    private const val DIRECTORY = 0x01100100 // O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    private const val FILE = 0x01000b02 // O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC
    private fun inspect(fd: Int, uid: Int, private: Boolean, directory: Boolean = true): Info {
        val info = stat(fd)
        require(info.mode and 0xf000 == if (directory) 0x4000 else 0x8000)
        require(info.uid == uid || !private && info.uid == 0) { "Untrusted transfer owner" }
        if (private) require(info.mode and 0x1ff == if (directory) 0x1c0 else 0x180)
        else require(info.mode and 0x12 == 0 || info.mode and 0x200 != 0) { "Untrusted transfer ancestor permissions" }
        require(directory || info.links == 1)
        requireMacTransferAcl(DesktopMacAdmissionAcl.inspect(fd), private, directory)
        return info
    }
    fun create(parent: Path): DesktopControlTransferFile {
        val absolute = parent.toAbsolutePath().normalize()
        var prefix = absolute.root
        for (name in absolute) {
            prefix = prefix.resolve(name)
            if (Files.isSymbolicLink(prefix)) {
                require(prefix in setOf(Path.of("/var"), Path.of("/tmp"))) { "Transfer link rejected" }
                require(Files.getAttribute(prefix, "unix:uid", NOFOLLOW_LINKS) == 0)
                require((Files.getAttribute(prefix.parent, "unix:mode", NOFOLLOW_LINKS) as Int) and 0x12 == 0)
            }
        }
        val resolved = parent.toRealPath()
        val uid = api.geteuid()
        val retained = mutableListOf<Int>()
        var directory = -1
        var container = -1
        var payload = -1
        val name = "vpn-control-transfer-${UUID.randomUUID()}"
        try {
            var current = api.open(resolved.root.toString(), DIRECTORY)
            check(current >= 0) { "Transfer root unavailable" }
            retained += current
            inspect(current, uid, false)
            for (part in resolved) {
                current = api.openat(current, part.toString(), DIRECTORY, 0)
                check(current >= 0) { "Transfer ancestor unavailable" }
                retained += current
                inspect(current, uid, false)
            }
            container = current
            check(api.mkdirat(container, name, 0x1c0) == 0) { "Private transfer directory unavailable" }
            directory = api.openat(container, name, DIRECTORY, 0)
            check(directory >= 0)
            retained += directory
            val identity = inspect(directory, uid, true)
            payload = api.openat(directory, "payload", FILE, 0x180)
            check(payload >= 0) { "Private transfer payload unavailable" }
            val payloadIdentity = inspect(payload, uid, true, directory = false)
            val pinnedDirectory = directory
            val pinnedParent = container
            val pinnedPayload = payload
            val openedChannel = DescriptorChannel(pinnedPayload)
            return object : DesktopControlTransferFile {
                override val channel: SeekableByteChannel = openedChannel
                override fun force() { check(api.fsync(pinnedPayload) == 0) { "Transfer synchronization failed" } }
                override fun publish(leaf: String) {
                    require(leaf.isNotBlank() && leaf !in setOf(".", "..") && '/' !in leaf && '\u0000' !in leaf)
                    val currentParent = api.open(resolved.toString(), DIRECTORY)
                    check(currentParent >= 0)
                    try {
                        val current = stat(currentParent)
                        val expected = stat(pinnedParent)
                        require(current.device == expected.device && current.inode == expected.inode) { "Export parent replaced" }
                    } finally { api.close(currentParent) }
                    val candidate = api.openat(pinnedDirectory, "payload", 0x01000100, 0) // RDONLY|NOFOLLOW|CLOEXEC
                    check(candidate >= 0)
                    try {
                        val actual = stat(candidate)
                        require(actual.device == payloadIdentity.device && actual.inode == payloadIdentity.inode) { "Export partial replaced" }
                    } finally { api.close(candidate) }
                    // RENAME_EXCL is atomic and refuses even a concurrently-created target.
                    check(api.renameatx_np(pinnedDirectory, "payload", pinnedParent, leaf, 4) == 0) { "Export publication failed" }
                    check(api.fsync(pinnedParent) == 0) { "Export publication synchronization failed" }
                }
                private var erased = false
                override fun erase() {
                    if (erased) return
                    erased = true
                    try {
                    val file = api.openat(pinnedDirectory, "payload", 0x01000100, 0)
                    if (file >= 0) {
                        try {
                            val actual = stat(file)
                            if (actual.device != payloadIdentity.device || actual.inode != payloadIdentity.inode) return
                            require(api.unlinkat(pinnedDirectory, "payload", 0) == 0)
                        } finally { api.close(file) }
                    } else {
                        val error = Native.getLastError()
                        if (error == 62) return // ELOOP: replacement symlink is not ours to remove.
                        require(error == 2)
                    }
                    val candidate = api.openat(pinnedParent, name, DIRECTORY, 0)
                    if (candidate >= 0) {
                        try {
                            val current = stat(candidate)
                            require(current.device == identity.device && current.inode == identity.inode) { "Transfer directory replaced" }
                            check(api.unlinkat(pinnedParent, name, 0x80) == 0) { "Transfer directory cleanup failed" }
                        } finally { api.close(candidate) }
                    } else require(Native.getLastError() == 2) { "Transfer directory replaced" }
                    } finally { retained.asReversed().forEach { api.close(it) } }
                }
            }
        } catch (error: Throwable) {
            if (payload >= 0) { api.close(payload); api.unlinkat(directory, "payload", 0) }
            if (directory >= 0) api.unlinkat(container, name, 0x80)
            retained.asReversed().forEach { api.close(it) }
            throw error
        }
    }

    private class DescriptorChannel(private val fd: Int) : SeekableByteChannel {
        private var open = true
        private var offset = 0L
        override fun isOpen() = open
        override fun close() { if (open) { check(api.close(fd) == 0); open = false } }
        override fun position(): Long { check(open); return offset }
        override fun position(newPosition: Long): SeekableByteChannel { check(open); require(newPosition >= 0); offset = newPosition; return this }
        override fun size(): Long { check(open); return stat(fd).size }
        override fun truncate(size: Long): SeekableByteChannel {
            check(open); require(size >= 0)
            if (size < size()) check(api.ftruncate(fd, size) == 0)
            offset = minOf(offset, size)
            return this
        }
        override fun read(dst: ByteBuffer): Int {
            check(open)
            if (!dst.hasRemaining()) return 0
            val bytes = ByteArray(minOf(dst.remaining(), 65536))
            val count = api.pread(fd, bytes, bytes.size.toLong(), offset)
            check(count in 0..bytes.size.toLong()) { "Transfer read failed" }
            if (count == 0L) return -1
            dst.put(bytes, 0, count.toInt()); offset += count
            return count.toInt()
        }
        override fun write(src: ByteBuffer): Int {
            check(open)
            if (!src.hasRemaining()) return 0
            val bytes = ByteArray(minOf(src.remaining(), 65536))
            src.duplicate().get(bytes)
            val count = api.pwrite(fd, bytes, bytes.size.toLong(), offset)
            check(count in 1..bytes.size.toLong()) { "Transfer write failed" }
            src.position(src.position() + count.toInt()); offset += count
            return count.toInt()
        }
    }
}
