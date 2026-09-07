package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue

/** Safe to report without leaking malformed input or an underlying parser exception. */
class ControlProtocolException(val code: ControlCode) : IllegalArgumentException(code.wireName)

/** Bounded wire-frame JSON. Logical documents use ControlDocumentCodec after transfer assembly. */
object ControlProtocolCodec {
    const val MAX_FRAME_BYTES = 1_048_576

    fun encodeValues(values: Map<String, ControlValue>): String = bounded(ControlDocumentCodec.encodeValues(values))
    fun decodeValues(frame: String): Map<String, ControlValue> = ControlDocumentCodec.decodeValues(bounded(frame))
    fun encodeRequest(request: ControlRequest): String = bounded(ControlDocumentCodec.encodeRequest(request))
    fun decodeRequest(frame: String): ControlRequest = ControlDocumentCodec.decodeRequest(bounded(frame))
    fun encodeResult(result: ControlResult): String = bounded(ControlDocumentCodec.encodeResult(result))
    fun decodeResult(frame: String): ControlResult = ControlDocumentCodec.decodeResult(bounded(frame))

    internal fun bounded(frame: String): String {
        if (frame.length > MAX_FRAME_BYTES || frame.encodeToByteArray().size > MAX_FRAME_BYTES)
            throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
        return frame
    }
}
