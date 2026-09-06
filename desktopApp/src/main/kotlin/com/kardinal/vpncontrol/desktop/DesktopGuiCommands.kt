package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode

internal fun desktopGuiSourceAction(openingId: String, owner: String?, revision: Long,
    command: com.kardinal.vpncontrol.model.ControlCommand): com.kardinal.vpncontrol.model.ControlRequest {
    require(command.operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.SOURCE_SET,
        com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_DELETE))
    return frontendSettingsRequest(openingId, owner, revision, command.arguments,
        command.operation.wireName + ":" + ControlProtocolCodec.encodeValues(command.arguments)).copy(command = command)
}

internal fun desktopGuiLocationAction(openingId: String, owner: String?, revision: Long,
    id: String, operation: com.kardinal.vpncontrol.model.ControlOperationId): com.kardinal.vpncontrol.model.ControlRequest {
    require(operation in setOf(com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_SELECT,
        com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_DELETE))
    val args = mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(id))
    return frontendSettingsRequest(openingId, owner, revision, args, operation.wireName + ":" + id)
        .copy(command = com.kardinal.vpncontrol.model.ControlCommand(operation, args))
}

/** Frontend feedback retains a stable code only, never controller response text or private inputs. */
internal fun desktopGuiCommandFailure(response: DesktopCliResponse): ControlCode? {
    if (response.success) return null
    val encoded = runCatching { ControlProtocolCodec.decodeResult(response.message) }.getOrNull()
    val code = encoded?.code ?: ControlCode.entries.firstOrNull { it.wireName == response.message }
    return code?.takeUnless { it.exitCode == 0 } ?: ControlCode.RUNTIME_FAILED
}

internal suspend fun executeDesktopGuiCommand(
    command: DesktopCliCommand,
    execute: suspend (DesktopCliCommand) -> DesktopCliResponse,
    onFailure: (ControlCode) -> Unit,
): DesktopCliResponse {
    val response = execute(command)
    desktopGuiCommandFailure(response)?.let(onFailure)
    return response
}

/** Capture the rendered configuration, never reinterpret a GUI row as a terminal name/index. */
internal fun desktopGuiBenchmarkCommand(
    index: Int,
    visible: List<DesktopLocationRecord>,
    configurationId: (DesktopLocationRecord) -> String?,
): DesktopCliCommand.LocationBenchmark? = visible.singleOrNull { it.index == index }?.let(configurationId)?.let {
    DesktopCliCommand.LocationBenchmark(target = "", configurationId = it)
}

internal fun resolveDesktopConfigurationReference(
    id: String,
    visible: List<DesktopLocationRecord>,
    configurationId: (DesktopLocationRecord) -> String?,
): Result<DesktopLocationRecord> = visible.singleOrNull { configurationId(it) == id }?.let(Result.Companion::success)
    ?: Result.failure(IllegalStateException("CONFLICT"))
