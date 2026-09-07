package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlTransferSpool
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID

/**
 * Ephemeral, unlinked file in the application's private cache. The caller must
 * supply Context.cacheDir, never a provider URI/client path or public storage.
 * Unlinking immediately means expiry, process death and renamed paths cannot leave
 * readable named payloads behind or redirect cleanup to another file.
 */
internal class AndroidControlTransferSpool private constructor(private val channel: FileChannel) : ControlTransferSpool {
    private var size = 0L
    private var erased = false

    @Synchronized override fun append(bytes: ByteArray) {
        check(!erased)
        require(bytes.size in 1..CHUNK && size <= Long.MAX_VALUE - bytes.size)
        channel.position(size)
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
        size += bytes.size
    }

    @Synchronized override fun read(offset: Long, length: Int): ByteArray {
        check(!erased)
        require(length in 0..CHUNK && offset >= 0 && offset <= size && length.toLong() <= size - offset)
        check(channel.size() == size)
        val bytes = ByteArray(length)
        try {
            channel.position(offset)
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) check(channel.read(buffer) > 0)
            return bytes
        } catch (error: Exception) { bytes.fill(0); throw error }
    }

    @Synchronized override fun sha256(): String {
        check(!erased)
        val digest = MessageDigest.getInstance("SHA-256")
        var offset = 0L
        while (offset < size) {
            val bytes = read(offset, minOf(CHUNK.toLong(), size - offset).toInt())
            try { digest.update(bytes); offset += bytes.size } finally { bytes.fill(0) }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    @Synchronized override fun erase() {
        erased = true
        channel.close()
        size = 0
    }

    override fun toString() = "AndroidControlTransferSpool(<redacted>)"

    companion object {
        private const val CHUNK = 65536
        fun create(privateCache: Path): AndroidControlTransferSpool {
            require(Files.isDirectory(privateCache, NOFOLLOW_LINKS) && !Files.isSymbolicLink(privateCache))
            val path = privateCache.resolve("control-transfer-${UUID.randomUUID()}")
            val channel = FileChannel.open(path, setOf(StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            try {
                Files.delete(path)
                return AndroidControlTransferSpool(channel)
            } catch (error: Exception) {
                channel.close()
                runCatching { Files.deleteIfExists(path) }
                throw error
            }
        }
    }
}
