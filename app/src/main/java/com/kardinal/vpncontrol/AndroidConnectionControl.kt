package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.util.concurrent.ConcurrentHashMap

/** Typed ON/RESTART execution under the existing owner admission lease. */
internal class AndroidConnectionControl(
    private val ownerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val observation: () -> AndroidRuntimeObservation,
    private val foregroundReady: () -> Boolean,
    private val vpnPrepared: () -> Boolean,
    private val interactions: AndroidControlInteractions,
    private val prepare: suspend (PersistedState) -> Result<ProfileSelection>,
    private val validate: (String) -> Unit,
    private val start: suspend (ProfileSelection, () -> Boolean) -> Result<Unit>,
    private val persist: suspend (ProfileSelection) -> Unit,
    private val pendingRestart: (PersistedState) -> Boolean?,
) {
    private val vpnTokens = ConcurrentHashMap<String, Boolean>()
    fun requiresVpnConsent(token: String): Boolean = vpnTokens[token] ?: true
    fun cancelConsentWait(operationId: String) = interactions.cancel(operationId)

    fun preflight(request: ControlRequest, state: PersistedState): ControlCode? {
        val live = observation()
        if (live.knowledge == AndroidRuntimeKnowledge.UNKNOWN) return ControlCode.UNAVAILABLE
        if (request.command.operation == ControlOperationId.ON && live.knowledge == AndroidRuntimeKnowledge.RUNNING) return null
        if ((!foregroundReady() || state.appMode == AppMode.VPN && !vpnPrepared()) && !request.interactive)
            return ControlCode.INTERACTION_REQUIRED
        return null
    }

    suspend fun execute(request: ControlRequest, operationId: String, awaitingUser: (Boolean) -> Boolean): ControlResult {
        var metadata: ControlCommitted<PersistedState>? = null
        var token: String? = null
        var dispatched = false
        fun result(code: ControlCode, warnings: List<String> = emptyList()): ControlResult {
            val committed = metadata
            val pending = committed?.value?.let(pendingRestart)
            return ControlResult(ownerId, request.requestId, code, committed?.revision ?: 0,
                operationId = operationId, restartRequired = pending ?: false,
                warnings = warnings + (if (committed == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
                    if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
        }
        return try {
            val committed = snapshot().also { metadata = it }
            if (request.controllerId != ownerId || committed.controllerId != ownerId ||
                request.ifRevision != null && request.ifRevision != committed.revision) return result(ControlCode.CONFLICT)
            preflight(request, committed.value)?.let {
                return result(if (it == ControlCode.UNAVAILABLE) ControlCode.RUNTIME_FAILED else it,
                    if (it == ControlCode.UNAVAILABLE) listOf("RUNTIME_OUTCOME_UNKNOWN", "RUNTIME_NOT_CHANGED") else emptyList())
            }
            if (request.command.operation == ControlOperationId.ON && observation().knowledge == AndroidRuntimeKnowledge.RUNNING)
                return result(ControlCode.OK)
            val mode = committed.value.appMode
            if (!foregroundReady() || mode == AppMode.VPN && !vpnPrepared()) {
                val interaction = interactions.create(operationId, request.command.operation)
                token = interaction
                vpnTokens[interaction] = mode == AppMode.VPN
                awaitingUser(true)
                val consent = interactions.await(interaction)
                if (!awaitingUser(false)) return result(ControlCode.CANCELLED)
                if (consent != ControlCode.OK) return result(consent)
            }
            fun eligible(): Boolean = foregroundReady() && (mode != AppMode.VPN || vpnPrepared())
            if (!eligible()) return result(ControlCode.INTERACTION_REQUIRED)
            val selection = prepare(committed.value).getOrElse { return result(ControlCode.INVALID_ARGUMENT) }
            try { validate(selection.runtimeConfigJson) } catch (_: Exception) { return result(ControlCode.INVALID_ARGUMENT) }
            // Validation/consent precede all runtime replacement; eligibility is checked
            // again on the main thread at the actual startForegroundService dispatch.
            val started = start(selection, ::eligible)
            dispatched = (started.exceptionOrNull() as? com.kardinal.vpncontrol.data.VpnCommandException)?.commandDispatched ?: started.isSuccess
            if (started.isFailure) {
                val error = started.exceptionOrNull()
                return result(if (!dispatched && !eligible()) ControlCode.INTERACTION_REQUIRED else ControlCode.RUNTIME_FAILED,
                    if ((error as? com.kardinal.vpncontrol.data.VpnCommandException)?.outcomeUnknown == true)
                        listOf("RUNTIME_OUTCOME_UNKNOWN") else emptyList())
            }
            if (observation().knowledge != AndroidRuntimeKnowledge.RUNNING)
                return result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_OUTCOME_UNKNOWN"))
            persist(selection)
            metadata = snapshot()
            result(ControlCode.OK)
        } catch (_: Exception) {
            // The persistence method may have committed before a subsequent step
            // failed. Under our lease this is the exact current committed metadata.
            metadata = runCatching { snapshot() }.getOrNull()
            result(if (dispatched) ControlCode.RUNTIME_FAILED else ControlCode.PERSISTENCE_FAILED,
                if (dispatched) listOf("RUNTIME_STARTED_PERSISTENCE_FAILED") else emptyList())
        } finally {
            token?.let { vpnTokens.remove(it); interactions.finish(it) }
        }
    }
}
