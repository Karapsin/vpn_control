package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID

/** One retained private file: payload buffers and metadata stay bounded regardless of upload size. */
internal class DesktopControlTransferSpool private constructor(
    private val directory: Path,
    private val payload: Path,
    private val channel: FileChannel,
) : ControlTransferSpool {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var size = 0L
    private var erased = false

    @Synchronized override fun append(bytes: ByteArray) {
        check(!erased)
        require(bytes.size in 1..CHUNK_BYTES && size <= Long.MAX_VALUE - bytes.size)
        channel.position(size)
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
        channel.force(false)
        digest.update(bytes)
        size += bytes.size
    }

    @Synchronized override fun read(offset: Long, length: Int): ByteArray {
        check(!erased)
        require(length in 0..CHUNK_BYTES && offset >= 0 && offset <= size && length.toLong() <= size - offset)
        val result = ByteArray(length)
        check(channel.size() == size)
        channel.position(offset)
        val buffer = ByteBuffer.wrap(result)
        while (buffer.hasRemaining()) check(channel.read(buffer) > 0)
        return result
    }

    @Synchronized override fun sha256(): String {
        check(!erased)
        return (digest.clone() as MessageDigest).digest().joinToString("") { "%02x".format(it) }
    }

    @Synchronized override fun erase() {
        // On a cleanup failure, a subsequent call retries the exact owned leaves.
        erased = true
        var failure: Exception? = null
        try { channel.close() }
        catch (error: Exception) { failure = failure ?: error }
        try { Files.deleteIfExists(payload) }
        catch (error: Exception) { failure = failure ?: error }
        try { Files.deleteIfExists(directory) }
        catch (error: Exception) { failure = failure ?: error }
        failure?.let { throw it }
        size = 0
        digest.reset()
    }

    override fun toString() = "DesktopControlTransferSpool(<redacted>)"

    companion object {
        private const val CHUNK_BYTES = 65536

        fun create(parent: Path = Path.of(System.getProperty("java.io.tmpdir"))): DesktopControlTransferSpool {
            val resolved = parent.toRealPath()
            val directory = if (Platform.isWindows()) {
                val token = WinNT.HANDLEByReference()
                check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
                val sid = try { Advapi32Util.getTokenAccount(token.value).sidString }
                finally { Kernel32.INSTANCE.CloseHandle(token.value) }
                resolved.resolve("vpn-control-transfer-${UUID.randomUUID()}").also {
                    JnaWindowsInstallNative().createDirectory(it.toString(), "O:${sid}G:${sid}D:P(A;;FA;;;$sid)", false)
                }
            } else Files.createTempDirectory(resolved, "vpn-control-transfer-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            try {
                require(Files.readAttributes(directory, BasicFileAttributes::class.java, NOFOLLOW_LINKS).isDirectory)
                if (Platform.isWindows()) {
                    val owner = Files.getOwner(directory, NOFOLLOW_LINKS)
                    require(owner == directory.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")))
                    val acl = requireNotNull(Files.getFileAttributeView(directory, AclFileAttributeView::class.java, NOFOLLOW_LINKS))
                    require(isPrivateControlAcl(owner, acl.acl))
                } else {
                    require(Files.getPosixFilePermissions(directory, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rwx------"))
                    if (Platform.isMac()) DesktopMacInstallJobAcl.requireAbsent(directory)
                }
                val payload = directory.resolve("payload")
                // Create empty with the native private ACL policy first. Only the invoking
                // account can replace children in this verified private directory. Open once
                // without following links, then use the retained descriptor for every byte.
                DesktopPrivateExportWriter.write(payload.toString(), byteArrayOf()).getOrThrow()
                val channel = FileChannel.open(payload, READ, WRITE, NOFOLLOW_LINKS)
                return DesktopControlTransferSpool(directory, payload, channel)
            } catch (error: Exception) {
                runCatching { Files.deleteIfExists(directory.resolve("payload")) }
                runCatching { Files.deleteIfExists(directory) }
                throw error
            }
        }
    }
}
