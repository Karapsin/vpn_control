package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Frontend-local optimistic guards. Picker completion never reopens/rebases the settings draft. */
internal class AndroidSshDraftControl(
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
) {
    private data class Guard(val owner: String, val revision: Long)
    private var opening: Guard? = null
    private var picker: Guard? = null
    private var saveRequest: ControlRequest? = null
    private var keyRequest: ControlRequest? = null
    suspend fun open(): HomeSshRouteSettings {
        val captured = snapshot()
        opening = Guard(captured.controllerId, captured.revision)
        saveRequest = null
        return captured.value.homeSshRouteSettings
    }
    fun close() { opening = null; saveRequest = null; cancelKeyPicker() }
    suspend fun beginKeyPicker() {
        val captured = snapshot()
        picker = Guard(captured.controllerId, captured.revision)
        keyRequest = null
    }
    fun cancelKeyPicker() { picker = null; keyRequest = null }
    suspend fun importKey(content: String): ControlResult {
        val guard = picker ?: return unavailable()
        val arguments = mapOf("input" to ControlValue.Text(content))
        val request = keyRequest?.takeIf { it.command.arguments == arguments }
            ?: request(guard, ControlOperationId.SSH_KEY_IMPORT, arguments).also { keyRequest = it }
        val result = execute(request)
        if (result.code == ControlCode.OK || result.code == ControlCode.CONFLICT) cancelKeyPicker()
        return result
    }
    suspend fun save(settings: HomeSshRouteSettings): ControlResult {
        val guard = opening ?: return unavailable()
        val patch = mapOf(
            "ssh.enabled" to ControlValue.BooleanValue(settings.enabled), "ssh.host" to ControlValue.Text(settings.host),
            "ssh.port" to ControlValue.IntegerValue(settings.port.toLong()), "ssh.user" to ControlValue.Text(settings.user),
            "ssh.host-keys" to ControlValue.ArrayValue(settings.hostKeys.map(ControlValue::Text)),
            "ssh.relay-port" to ControlValue.IntegerValue(settings.relayPort.toLong()))
        val arguments = mapOf("input" to ControlValue.Text(ControlDocumentCodec.encodeValues(patch)))
        val request = saveRequest?.takeIf { it.command.arguments == arguments }
            ?: request(guard, ControlOperationId.SETTINGS_APPLY, arguments).also { saveRequest = it }
        return execute(request)
    }
    private fun request(guard: Guard, operation: ControlOperationId, arguments: Map<String, ControlValue>) =
        ControlRequest(UUID.randomUUID().toString(), ControlCommand(operation, arguments),
            controllerId = guard.owner, ifRevision = guard.revision)
    private fun unavailable() = ControlResult(null, UUID.randomUUID().toString(), ControlCode.CONFLICT, 0,
        warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE"))
}
