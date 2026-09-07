package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlTransferSpool
import java.nio.ByteBuffer
import java.nio.file.Path
import java.security.MessageDigest

/** One retained private file: payload buffers and metadata stay bounded regardless of upload size. */
internal class DesktopControlTransferSpool private constructor(
    private val file: DesktopControlTransferFile,
) : ControlTransferSpool {
    private val channel get() = file.channel
    private val digest = MessageDigest.getInstance("SHA-256")
    private var size = 0L
    private var erased = false

    @Synchronized override fun append(bytes: ByteArray) {
        check(!erased)
        require(bytes.size in 1..CHUNK_BYTES && size <= Long.MAX_VALUE - bytes.size)
        channel.position(size)
        val buffer = ByteBuffer.wrap(bytes)
        while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
        file.force()
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
        try { file.erase() }
        catch (error: Exception) { failure = failure ?: error }
        failure?.let { throw it }
        size = 0
        digest.reset()
    }

    override fun toString() = "DesktopControlTransferSpool(<redacted>)"

    companion object {
        private const val CHUNK_BYTES = 65536

        fun create(parent: Path = Path.of(System.getProperty("java.io.tmpdir"))): DesktopControlTransferSpool {
            return DesktopControlTransferSpool(DesktopControlTransferParent.create(parent))
        }
    }
}
