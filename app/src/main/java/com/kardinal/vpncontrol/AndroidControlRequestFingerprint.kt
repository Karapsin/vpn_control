package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlValue
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.security.MessageDigest

/** Identical legacy canonical JSON/suffix/UTF8 bytes, with bounded encoding buffers. */
internal fun androidControlRequestFingerprint(values: Map<String, ControlValue>, revision: Long?, interactive: Boolean,
    scheduled: Boolean): String = fingerprint(revision, interactive, scheduled) {
        ControlDocumentCodec.writeValues(values.toSortedMap(), it)
    }

internal fun androidControlInputFingerprint(source: com.kardinal.vpncontrol.control.ControlCharacterSource,
    revision: Long?): String = fingerprint(revision, false, false) {
        it.append("{\"input\":")
        ControlDocumentCodec.writeQuotedText(source, it)
        it.append('}')
    }

private fun fingerprint(revision: Long?, interactive: Boolean, scheduled: Boolean, values: (Appendable) -> Unit): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val sink = object : OutputStream() {
        override fun write(value: Int) = digest.update(value.toByte())
        override fun write(bytes: ByteArray, offset: Int, count: Int) = digest.update(bytes, offset, count)
    }
    // Keep one encoder across all chunks, including split surrogate pairs. Its
    // malformed-unit replacement matches String.toByteArray(UTF_8) exactly.
    OutputStreamWriter(sink, Charsets.UTF_8).buffered(8192).use { writer ->
        values(writer)
        writer.append('\u0000').append(revision.toString()).append('\u0000').append(interactive.toString())
            .append("\u0000scheduled=").append(scheduled.toString())
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
