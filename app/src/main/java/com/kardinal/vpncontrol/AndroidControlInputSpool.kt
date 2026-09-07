package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCharacterSource
import com.kardinal.vpncontrol.control.ControlTransferSpool

/** Private UTF16-code-unit storage; JSON lone surrogates must not be changed by UTF8 encoding. */
internal class AndroidControlInputSpool(private val storage: ControlTransferSpool) : Appendable, AutoCloseable {
    private val buffer = ByteArray(65536)
    private var used = 0
    private var sealed = false
    private var closed = false
    private var ascii = true
    var length: Long = 0
        private set

    override fun append(value: Char): Appendable {
        check(!sealed && !closed)
        buffer[used++] = value.code.toByte()
        buffer[used++] = (value.code ushr 8).toByte()
        length = Math.addExact(length, 1)
        if (value.code > 127) ascii = false
        if (used == buffer.size) flush()
        return this
    }
    override fun append(value: CharSequence?): Appendable = append(value, 0, value?.length ?: 4)
    override fun append(value: CharSequence?, start: Int, end: Int): Appendable {
        val text = value ?: "null"
        require(start >= 0 && start <= end && end <= text.length)
        for (index in start until end) append(text[index])
        return this
    }
    fun seal() { check(!closed); if (!sealed) { flush(); sealed = true } }
    private fun flush() {
        if (used == 0) return
        val chunk = buffer.copyOf(used)
        try { storage.append(chunk); used = 0 }
        catch (_: Exception) { throw java.io.IOException("Private input unavailable") }
        finally { chunk.fill(0); buffer.fill(0) }
    }
    fun source(): ControlCharacterSource {
        check(sealed && !closed)
        var offset = 0L
        var chunk = ByteArray(0)
        var index = 0
        return ControlCharacterSource {
            check(!closed)
            if (offset == length * 2) -1 else {
                if (index == chunk.size) {
                    chunk.fill(0)
                    chunk = try { storage.read(offset, minOf(65536L, length * 2 - offset).toInt()) }
                        catch (_: Exception) { throw java.io.IOException("Private input unavailable") }
                    index = 0
                }
                val value = (chunk[index].toInt() and 255) or ((chunk[index + 1].toInt() and 255) shl 8)
                index += 2; offset += 2
                if (offset == length * 2) chunk.fill(0)
                value
            }
        }
    }
    /** Compatibility path for non-routing commands; never used by the streamed routing owner. */
    fun materialize(): String {
        if (length > Int.MAX_VALUE) throw OutOfMemoryError()
        val input = source()
        return if (ascii) {
            val bytes = ByteArray(length.toInt()) { input.read().toByte() }
            bytes.decodeToString()
        } else CharArray(length.toInt()) { input.read().toChar() }.concatToString()
    }
    override fun close() {
        if (!closed) { closed = true; buffer.fill(0); storage.erase() }
    }
    override fun toString(): String = "AndroidControlInputSpool(<redacted>)"
}
