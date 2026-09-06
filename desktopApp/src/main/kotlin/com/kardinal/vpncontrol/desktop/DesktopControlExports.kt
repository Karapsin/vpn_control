package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*

/** The owner returns content; only the invoking client interprets destinations/formats. */
internal object DesktopControlExports {
    val operations = setOf(ControlOperationId.LOCATIONS_EXPORT, ControlOperationId.ROUTING_EXPORT,
        ControlOperationId.DIAGNOSTICS_EXPORT)

    fun write(response: DesktopCliResponse, output: String, format: String,
              writeText: (String, String) -> Result<Unit>, writeBinary: (String, ByteArray) -> Result<Unit>): DesktopCliResponse {
        val result = ControlProtocolCodec.decodeResult(response.message)
        fun finish(code: ControlCode, message: String = "", data: Map<String, ControlValue> = emptyMap()): DesktopCliResponse {
            val completed = result.copy(code = code, message = message, data = data)
            return DesktopCliResponse(completed.ok, ControlProtocolCodec.encodeResult(completed), completed.exitCode)
        }
        if (!result.ok) return finish(result.code, result.message)
        if (!result.final || result.code != ControlCode.OK || output == "-") return finish(ControlCode.INCOMPATIBLE_PROTOCOL)
        val content = (result.data["content"] as? ControlValue.Text)?.value
            ?: return finish(ControlCode.INCOMPATIBLE_PROTOCOL)
        val size: Int
        val written: Result<Unit>
        if (format == "qr-png") {
            val png = DesktopQrImage.encode(content)
            if (png.isFailure) return finish(ControlCode.INVALID_ARGUMENT, png.exceptionOrNull()?.message ?: "INVALID_ARGUMENT")
            val bytes = png.getOrThrow()
            size = bytes.size
            written = runCatching { writeBinary(output, bytes).getOrThrow() }
        } else {
            size = content.toByteArray(Charsets.UTF_8).size
            written = runCatching { writeText(output, content).getOrThrow() }
        }
        if (written.isFailure) return finish(ControlCode.PERSISTENCE_FAILED, "Could not write export output.")
        return finish(ControlCode.OK, data = mapOf("format" to ControlValue.Text(format), "bytes" to ControlValue.IntegerValue(size.toLong())))
    }
}
