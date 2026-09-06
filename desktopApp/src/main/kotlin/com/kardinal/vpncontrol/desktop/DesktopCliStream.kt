package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Bounded polling of one authenticated owner. Never starts/rebinds a controller or mutates runtime. */
internal object DesktopCliStream {
    fun run(invocation: ControlCliParseResult.Invocation,
            requestCommand: (DesktopCliCommand) -> DesktopCliResponse,
            output: (String) -> Unit, progress: (String) -> Unit,
            pause: () -> Unit = { Thread.sleep(250) },
            active: () -> Boolean = { !Thread.currentThread().isInterrupted }): Int {
        val logs = invocation.operation == ControlOperationId.LOGS
        var ownerId: String? = null
        var cursor: String? = null
        var previous: ControlResult? = null
        fun emit(result: ControlResult) {
            if (invocation.client.json) output(ControlProtocolCodec.encodeResult(result))
            else if (result.code != ControlCode.OK) progress(result.code.wireName)
            else if (logs) {
                if ("LOG_HISTORY_GAP" in result.warnings) progress("LOG_HISTORY_GAP")
                val entries = (result.data["entries"] as? ControlValue.ArrayValue)?.values.orEmpty()
                for (entry in entries) {
                    val fields = (entry as ControlValue.ObjectValue).values
                    progress("${(fields["createdAtEpochMillis"] as ControlValue.IntegerValue).value}\t${kotlinx.serialization.json.JsonPrimitive((fields["message"] as ControlValue.Text).value)}")
                }
            } else progress(ControlProtocolCodec.encodeValues(result.data))
        }
        fun failure(code: ControlCode): Int {
            val result = previous?.copy(requestId = UUID.randomUUID().toString(), code = code, final = true,
                data = emptyMap(), message = code.wireName, warnings = previous!!.warnings + "LAST_OBSERVED_METADATA")
                ?: ControlProtocolCodec.decodeResult(desktopCliJsonFailure(code, UUID.randomUUID().toString()).message)
            emit(result)
            return code.exitCode
        }
        val expectedFlags = if (logs) setOf("--follow") else setOf("--watch")
        if (invocation.operation !in setOf(ControlOperationId.STATUS, ControlOperationId.STATS, ControlOperationId.LOGS) ||
            invocation.flags != expectedFlags || invocation.client.copy(json = false, timeoutSeconds = 600) != ControlClientOptions()) {
            return failure(ControlCode.UNSUPPORTED)
        }
        try {
            while (active()) {
                val arguments = if (logs) buildMap<String, ControlValue> {
                    // --limit applies to initial history only. Zero means follow new records.
                    put("limit", ControlValue.Text(if (cursor == null) invocation.options["--limit"] ?: "100" else "100"))
                    cursor?.let { put("after", ControlValue.Text(it)) }
                } else emptyMap()
                val request = ControlRequest(UUID.randomUUID().toString(), ControlCommand(invocation.operation, arguments), controllerId = ownerId)
                val response = desktopCliJsonResponse(request,
                    requestCommand(DesktopCliCommand.ControlSubmit(request, invocation.client.timeoutSeconds)))
                val result = ControlProtocolCodec.decodeResult(response.message)
                if (!result.ok) { emit(result); return result.exitCode }
                if (result.code != ControlCode.OK || !result.final || result.controllerId.isNullOrBlank() ||
                    ownerId != null && result.controllerId != ownerId) return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                ownerId = result.controllerId
                val warnings = result.warnings.toMutableList()
                var publish = true
                if (logs) {
                    val entries = (result.data["entries"] as? ControlValue.ArrayValue)?.values
                        ?: return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                    val next = (result.data["nextCursor"] as? ControlValue.Text)?.value
                        ?: return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                    val gap = (result.data["gap"] as? ControlValue.BooleanValue)?.value
                        ?: return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                    val ids = entries.map { entry ->
                        val fields = (entry as? ControlValue.ObjectValue)?.values
                            ?: return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                        if (fields["message"] !is ControlValue.Text || fields["createdAtEpochMillis"] !is ControlValue.IntegerValue)
                            return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                        (fields["id"] as? ControlValue.Text)?.value ?: return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                    }
                    if (next.isBlank() || ids.any(String::isBlank) || ids.distinct().size != ids.size ||
                        entries.isNotEmpty() && (ids.last() != next || cursor in ids))
                        return failure(ControlCode.INCOMPATIBLE_PROTOCOL)
                    if (gap) warnings += "LOG_HISTORY_GAP"
                    publish = previous == null || entries.isNotEmpty() || gap
                    cursor = next
                }
                previous = result
                if (publish) emit(result.copy(final = false, warnings = warnings))
                if (if (invocation.client.json) System.out.checkError() else System.err.checkError()) return 130
                pause()
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (_: java.io.IOException) {
            return 130 // Closed output: stop polling; never cancel owner work.
        }
        return failure(ControlCode.CANCELLED)
    }
}
