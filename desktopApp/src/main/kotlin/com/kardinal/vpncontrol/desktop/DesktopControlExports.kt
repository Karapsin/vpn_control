package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*

/** The owner returns content; only the invoking client interprets destinations/formats. */
internal object DesktopControlExports {
    val operations = setOf(ControlOperationId.LOCATIONS_EXPORT, ControlOperationId.ROUTING_EXPORT,
        ControlOperationId.DIAGNOSTICS_EXPORT)

    /** A failed raw sink may already contain a prefix; callers report failure on stderr only. */
    fun writeRaw(content: String, format: String,
                 writeBinary: (String, ByteArray) -> Result<Unit>): ControlCode {
        if (format == "qr-png") {
            val png = DesktopQrImage.encode(content).getOrNull() ?: return ControlCode.INVALID_ARGUMENT
            return if (runCatching { writeBinary("-", png).getOrThrow() }.isSuccess) ControlCode.OK
                else ControlCode.PERSISTENCE_FAILED
        }
        return if (runCatching {
            DesktopExportUtf8.encode(content) { bytes, count ->
                writeBinary("-", bytes.copyOf(count)).getOrThrow()
            }
        }.isSuccess) ControlCode.OK else ControlCode.PERSISTENCE_FAILED
    }

    fun write(response: DesktopCliResponse, output: String, format: String,
              writeText: (String, String) -> Result<Unit>, writeBinary: (String, ByteArray) -> Result<Unit>): DesktopCliResponse {
        val result = ControlDocumentCodec.decodeResult(response.message)
        fun finish(code: ControlCode, message: String = "", data: Map<String, ControlValue> = emptyMap()): DesktopCliResponse {
            val completed = result.copy(code = code, message = message, data = data)
            return DesktopCliResponse(completed.ok, ControlDocumentCodec.encodeResult(completed), completed.exitCode)
        }
        if (!result.ok) return finish(result.code, result.message)
        if (!result.final || result.code != ControlCode.OK || output == "-") return finish(ControlCode.INCOMPATIBLE_PROTOCOL)
        val content = (result.data["content"] as? ControlValue.Text)?.value
            ?: return finish(ControlCode.INCOMPATIBLE_PROTOCOL)
        val size: Long
        val written: Result<Unit>
        if (format == "qr-png") {
            val png = DesktopQrImage.encode(content)
            if (png.isFailure) return finish(ControlCode.INVALID_ARGUMENT, png.exceptionOrNull()?.message ?: "INVALID_ARGUMENT")
            val bytes = png.getOrThrow()
            size = bytes.size.toLong()
            written = runCatching { writeBinary(output, bytes).getOrThrow() }
        } else {
            size = DesktopExportUtf8.byteCount(content)
            written = runCatching { writeText(output, content).getOrThrow() }
        }
        if (written.isFailure) return finish(ControlCode.PERSISTENCE_FAILED, "Could not write export output.")
        return finish(ControlCode.OK, data = mapOf("format" to ControlValue.Text(format), "bytes" to ControlValue.IntegerValue(size)))
    }
}
