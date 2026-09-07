package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.QrExportPolicy
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.RoutingRules
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.OutputStreamWriter

/** Count the complete export while retaining at most the existing QR policy's payload budget. */
internal object AndroidRoutingQrExport {
    data class Result(val byteCount: Long, val payload: String?)
    fun prepare(rules: RoutingRules, exportedAt: String? = null): Result {
        val captured = ByteArrayOutputStream(QrExportPolicy.MAX_UTF8_BYTES)
        var count = 0L
        val sink = object : OutputStream() {
            override fun write(value: Int) {
                count++
                if (count <= QrExportPolicy.MAX_UTF8_BYTES) captured.write(value)
            }
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                val remaining = (QrExportPolicy.MAX_UTF8_BYTES - count).coerceAtLeast(0).toInt()
                if (remaining > 0) captured.write(bytes, offset, minOf(remaining, length))
                count = Math.addExact(count, length.toLong())
            }
        }
        OutputStreamWriter(sink, Charsets.UTF_8).buffered(8192).use { RoutingRulesTransfer.writeExport(rules, exportedAt, it) }
        return Result(count, if (count <= QrExportPolicy.MAX_UTF8_BYTES) captured.toString("UTF-8") else null)
    }
}
