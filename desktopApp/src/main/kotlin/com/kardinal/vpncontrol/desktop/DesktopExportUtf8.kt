package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** Encodes an already captured document without allocating a second document-sized byte array. */
internal object DesktopExportUtf8 {
    const val CHUNK_BYTES = 8192

    fun byteCount(text: CharSequence): Long {
        var total = 0L
        encode(text) { _, count -> total = Math.addExact(total, count.toLong()) }
        return total
    }

    // emit must consume the reusable buffer synchronously; only its first count bytes are valid.
    fun encode(text: CharSequence, emit: (ByteArray, Int) -> Unit) {
        val encoder = Charsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
        val input = CharBuffer.wrap(text)
        val output = ByteBuffer.allocate(CHUNK_BYTES)
        fun drain() {
            if (output.position() != 0) emit(output.array(), output.position())
            output.clear()
        }
        while (true) {
            val result = encoder.encode(input, output, true)
            drain()
            if (result.isUnderflow) break
            result.throwExceptionIfError()
        }
        while (true) {
            val result = encoder.flush(output)
            drain()
            if (result.isUnderflow) break
            result.throwExceptionIfError()
        }
    }

    private fun java.nio.charset.CoderResult.throwExceptionIfError() {
        if (isError) throwException()
    }
}
