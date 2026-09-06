package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult

internal fun desktopCliWantsJson(arguments: List<String>): Boolean =
    arguments.takeWhile { it != "--" }.contains("--json")

/** Local errors have no authoritative owner snapshot; explicitly mark that absence. */
internal fun desktopCliJsonFailure(code: ControlCode, requestId: String, operationId: String? = null): DesktopCliResponse {
    val result = ControlResult(null, requestId, code, configurationRevision = 0,
        message = code.wireName, warnings = listOf("OWNER_METADATA_UNAVAILABLE"), operationId = operationId,
        final = code !in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN))
    return DesktopCliResponse(false, ControlProtocolCodec.encodeResult(result), code.exitCode)
}

internal fun desktopCliJsonResponse(request: ControlRequest, response: DesktopCliResponse): DesktopCliResponse {
    val result = runCatching { ControlProtocolCodec.decodeResult(response.message) }.getOrNull()
    if (result != null && result.requestId == request.requestId && result.exitCode == response.exitCode &&
        result.ok == response.success && (request.controllerId == null || result.controllerId == request.controllerId ||
            result.code == ControlCode.CONFLICT)) {
        return response
    }
    val code = when {
        result != null || response.success -> ControlCode.INCOMPATIBLE_PROTOCOL
        response.isDesktopAppNotRunning -> ControlCode.UNAVAILABLE
        response.exitCode == 2 -> ControlCode.entries.firstOrNull {
            it.exitCode == 2 && it.wireName == response.message
        } ?: ControlCode.OUTCOME_UNKNOWN
        else -> ControlCode.INCOMPATIBLE_PROTOCOL
    }
    // Never copy transport text, paths or exceptions into script output.
    val knownOperationId = if (request.command.operation in setOf(
            com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_WAIT,
            com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS,
            com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_CANCEL))
        (request.command.arguments["id"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value else null
    return desktopCliJsonFailure(code, request.requestId, knownOperationId)
}
