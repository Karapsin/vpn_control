package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlOperationRegistry
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlReadLogic
import com.kardinal.vpncontrol.control.ControlSettingsLogic
import com.kardinal.vpncontrol.control.ControlConfigurationInspection
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout

/** Bounded transport adapter for committed reads and application-owned typed operations. */
internal class AndroidControlReader(
    val controllerId: String,
    private val snapshot: suspend () -> PersistedState,
    private val clockMillis: () -> Long = System::currentTimeMillis,
    private val readTimeoutMillis: Long = 10_000,
    private val runtimeObservation: () -> AndroidRuntimeObservation = { AndroidRuntimeObservation() },
    private val committedSnapshot: (suspend () -> com.kardinal.vpncontrol.control.ControlCommitted<PersistedState>)? = null,
    private val pendingRestart: (PersistedState) -> Boolean? = { null },
    private val settingsWrite: (suspend (ControlRequest) -> ControlResult)? = null,
    private val operationIdForRequest: (String) -> String? = { null },
    private val statusSnapshot: ((PersistedState) -> AndroidControlStatus)? = null,
    private val systemLanguageCode: () -> String = { java.util.Locale.getDefault().language },
    private val credentialPresent: ((PersistedState) -> Boolean)? = null,
    private val updateSnapshot: (() -> AppUpdateState)? = null,
    private val updateInspection: (() -> Map<String, ControlValue>)? = null,
    private val diagnosticsExport: (suspend (PersistedState) -> String)? = null,
    private val installedApps: (suspend () -> List<InstalledApp>)? = null,
) {
    suspend fun execute(bytes: ByteArray, transferId: String): ByteArray {
        val request = runCatching {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            ControlProtocolCodec.decodeRequest(text)
        }.getOrElse { return encode(result(transferId, ControlCode.INVALID_ARGUMENT)) }
        // Once decoding succeeds, even timeout/IO/oversize failures retain the request identity.
        return try {
            val response = encode(withTimeout(readTimeoutMillis) { read(request) })
            if (response.size <= 1_048_576) response else failure(request.requestId)
        } catch (_: TimeoutCancellationException) {
            encode(result(request.requestId, ControlCode.TIMEOUT).copy(operationId =
                if (request.command.operation in AndroidSettingsControl.inspectionOperations)
                    (request.command.arguments["id"] as? ControlValue.Text)?.value else operationIdForRequest(request.requestId)))
        } catch (_: Exception) {
            failure(request.requestId)
        }
    }

    suspend fun read(request: ControlRequest): ControlResult {
        if (request.controllerId != null && request.controllerId != controllerId) {
            return result(request.requestId, ControlCode.CONFLICT)
        }
        if (request.command.operation in AndroidSettingsControl.operations && settingsWrite != null) return settingsWrite.invoke(request)
        if (request.command.operation !in supported) return result(request.requestId, ControlCode.UNSUPPORTED)
        if (request.ifRevision != null || request.interactive || request.asynchronous) {
            return result(request.requestId, ControlCode.INVALID_ARGUMENT)
        }
        val command = request.command
        val committed = committedSnapshot?.invoke()
        var pending = committed?.value?.let(pendingRestart)
        fun response(code: ControlCode, data: Map<String, ControlValue> = emptyMap()) =
            result(request.requestId, code, data, committed?.revision, pending)
        if (command.operation == ControlOperationId.CAPABILITIES) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            return response(ControlCode.OK, mapOf(
                "scope" to ControlValue.Text(if (settingsWrite == null) "android-read-only-provider" else "android-provider"),
                "publicRevisionGuards" to ControlValue.BooleanValue(settingsWrite != null),
                "runtimeReadinessChecked" to ControlValue.BooleanValue(false),
                "operations" to ControlValue.ArrayValue(ControlOperationRegistry.operations.map {
                    ControlValue.ObjectValue(mapOf(
                        "id" to ControlValue.Text(it.id.wireName),
                        "supported" to ControlValue.BooleanValue(it.id in supported || settingsWrite != null && it.id in AndroidSettingsControl.operations),
                        "reasonCode" to if (it.id in supported || settingsWrite != null && it.id in AndroidSettingsControl.operations)
                            ControlValue.Null else ControlValue.Text("NOT_IMPLEMENTED"),
                    ))
                }),
            ))
        }
        val persisted = committed?.value ?: snapshot()
        pending = pendingRestart(persisted)
        if (command.operation == ControlOperationId.ROUTING_APPS_LIST) {
            if (com.kardinal.vpncontrol.control.ControlCommandArguments.decode(command) == null)
                return response(ControlCode.INVALID_ARGUMENT)
            val apps = installedApps?.invoke() ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, com.kardinal.vpncontrol.data.AndroidRoutingControl.list(persisted, command.arguments, apps))
        }
        if (command.operation == ControlOperationId.DIAGNOSTICS_EXPORT) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val exporter = diagnosticsExport ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, mapOf("content" to ControlValue.Text(exporter(persisted))))
        }
        if (command.operation == ControlOperationId.UPDATES_STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            updateInspection?.let { return response(ControlCode.OK, it()) }
            val update = updateSnapshot?.invoke() ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, AndroidControlUpdateInspection.read(update))
        }
        if (command.operation == ControlOperationId.SSH_KEY_STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val present = credentialPresent?.invoke(persisted) ?: return response(ControlCode.UNAVAILABLE)
            return response(ControlCode.OK, mapOf("present" to ControlValue.BooleanValue(present)))
        }
        if (command.operation in AndroidControlLocationInspection.operations) {
            val inspected = AndroidControlLocationInspection.read(
                MainUiStateProjector.mergePersistedState(MainUiState(), persisted), command,
                com.kardinal.vpncontrol.shared.ui.AppStrings(persisted.appLanguage.effective(systemLanguageCode())))
            return inspected.fold({ response(ControlCode.OK, it) }, {
                response((it as? ControlProtocolException)?.code ?: ControlCode.INVALID_ARGUMENT)
            })
        }
        if (command.operation in ControlConfigurationInspection.operations) {
            val inspected = ControlConfigurationInspection.read(
                MainUiStateProjector.mergePersistedState(MainUiState(), persisted), command, clockMillis())
            return inspected.fold({ response(ControlCode.OK, it) }, {
                response((it as? ControlProtocolException)?.code ?: ControlCode.INVALID_ARGUMENT)
            })
        }
        if (command.operation == ControlOperationId.STATUS) {
            if (command.arguments.isNotEmpty()) return response(ControlCode.INVALID_ARGUMENT)
            val status = statusSnapshot?.invoke(persisted) ?: return response(ControlCode.UNAVAILABLE,
                mapOf("runtimeRunning" to ControlValue.Null, "restartRequired" to ControlValue.Null,
                    "runtimeObservation" to ControlValue.Text("unknown")))
            pending = status.pending
            return response(if (status.authoritative) ControlCode.OK else ControlCode.UNAVAILABLE, status.data)
        }
        val data = when (command.operation) {
            ControlOperationId.SETTINGS_SHOW -> {
                if (command.arguments.keys.any { it != "key" }) return response(ControlCode.INVALID_ARGUMENT)
                val settings = ControlSettingsLogic.inspect(persisted)
                if (command.arguments.isEmpty()) settings else {
                    val key = (command.arguments["key"] as? ControlValue.Text)?.value
                        ?: return response(ControlCode.INVALID_ARGUMENT)
                    val value = settings[key] ?: return response(ControlCode.NOT_FOUND)
                    mapOf(key to value)
                }
            }
            else -> ControlReadLogic.read(
                MainUiStateProjector.mergePersistedState(MainUiState(), persisted), command, clockMillis(),
            ).getOrElse { return response(ControlCode.INVALID_ARGUMENT) }
        }
        val observedData = if (command.operation == ControlOperationId.STATS) {
            runtimeObservation().stats(data, clockMillis())
        } else data
        return response(ControlCode.OK, observedData)
    }

    private fun failure(requestId: String): ByteArray = encode(result(requestId, ControlCode.UNAVAILABLE))

    private fun result(id: String, code: ControlCode, data: Map<String, ControlValue> = emptyMap(), revision: Long? = null, pending: Boolean? = null) = ControlResult(
        controllerId = controllerId, requestId = id, code = code, configurationRevision = revision ?: 0,
        data = data, final = code != ControlCode.TIMEOUT, restartRequired = pending ?: false,
        warnings = (if (revision == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
            (if (data["runtimeObservation"] == ControlValue.Text("running") || data["runtimeObservation"] == ControlValue.Text("stopped"))
                emptyList() else listOf("ACTIVE_RUNTIME_IDENTITY_UNAVAILABLE")) +
            (if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()),
    )

    private fun encode(result: ControlResult): ByteArray = ControlProtocolCodec.encodeResult(result).toByteArray(Charsets.UTF_8)

    companion object {
        val supported = ControlReadLogic.operations + ControlConfigurationInspection.operations + AndroidControlLocationInspection.operations +
            setOf(ControlOperationId.CAPABILITIES, ControlOperationId.SETTINGS_SHOW, ControlOperationId.STATUS,
                ControlOperationId.SSH_KEY_STATUS, ControlOperationId.UPDATES_STATUS, ControlOperationId.DIAGNOSTICS_EXPORT,
                ControlOperationId.ROUTING_APPS_LIST)
    }
}
