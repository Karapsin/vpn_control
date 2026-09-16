package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.LocationConfigs
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
    private val findBestTokens = ConcurrentHashMap<String, String>()
    fun requiresVpnConsent(token: String): Boolean = vpnTokens[token] ?: true
    fun cancelConsentWait(operationId: String) = interactions.cancel(operationId)
    fun finishFindBestInteraction(operationId: String) {
        findBestTokens.remove(operationId)?.let { token ->
            vpnTokens.remove(token)
            interactions.finish(token)
        }
    }

    suspend fun prepareFindBest(request: ControlRequest, id: String, state: PersistedState,
        awaitingUser: (Boolean) -> Boolean): ControlCode {
        if (observation().knowledge == AndroidRuntimeKnowledge.UNKNOWN) return ControlCode.UNAVAILABLE
        // An already-running retained foreground service needs no new component launch.
        fun eligible() = (observation().knowledge == AndroidRuntimeKnowledge.RUNNING || foregroundReady()) &&
            (state.appMode != AppMode.VPN || vpnPrepared())
        if (eligible()) return ControlCode.OK
        if (!request.interactive) return ControlCode.INTERACTION_REQUIRED
        val token = interactions.create(id, ControlOperationId.FIND_BEST)
        vpnTokens[token] = state.appMode == AppMode.VPN
        var retained = false
        return try {
            if (!awaitingUser(true)) return ControlCode.CANCELLED
            val answer = interactions.await(token)
            if (!awaitingUser(false)) ControlCode.CANCELLED
            else if (answer != ControlCode.OK) answer
            else if (eligible() && interactions.retainGrantedSearch(token)) {
                // Planning and probes may take longer than the consent callback.
                // Keep the exact foreground Activity through native dispatch and
                // cleanup; the owner releases it even on cancellation or failure.
                check(findBestTokens.putIfAbsent(id, token) == null)
                retained = true
                ControlCode.OK
            } else ControlCode.INTERACTION_REQUIRED
        } finally {
            if (!retained) { vpnTokens.remove(token); interactions.finish(token) }
        }
    }

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
        var initialRevision: Long? = null
        var token: String? = null
        var dispatched = false
        var committing: ProfileSelection? = null
        fun result(code: ControlCode, warnings: List<String> = emptyList()): ControlResult {
            val committed = metadata
            val pending = committed?.value?.let(pendingRestart)
            return ControlResult(ownerId, request.requestId, code, committed?.revision ?: 0,
                operationId = operationId, restartRequired = pending ?: false,
                warnings = warnings + (if (committed == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()) +
                    if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
        }
        return try {
            val committed = snapshot().also { metadata = it; initialRevision = it.revision }
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
            // From this point a thrown response can follow a durable write. Keep
            // the exact selection so a fresh owner snapshot can reconcile it.
            committing = selection
            persist(selection)
            metadata = snapshot()
            result(ControlCode.OK)
        } catch (_: Exception) {
            metadata = runCatching { snapshot() }.getOrNull()
            val committed = metadata
            if (dispatched && committed != null && committed.revision != initialRevision && committing?.let {
                    // Matching an unchanged snapshot could merely describe the
                    // pre-existing selected runtime. A changed revision is the
                    // owner-held proof that this persistence transaction landed.
                    committed.controllerId == ownerId && committed.value.matches(it)
                } == true) {
                // A response failure after an exact durable commit must not make
                // callers retry and replace the already-started runtime.
                result(ControlCode.OK, listOf("POST_COMMIT_RESULT_UNAVAILABLE"))
            } else result(if (dispatched) ControlCode.RUNTIME_FAILED else ControlCode.PERSISTENCE_FAILED,
                if (dispatched) listOf("RUNTIME_STARTED_PERSISTENCE_FAILED") else emptyList())
        } finally {
            token?.let { vpnTokens.remove(it); interactions.finish(it) }
        }
    }

    private fun PersistedState.matches(selection: ProfileSelection): Boolean =
        selectedProfileName == selection.profile.remarks &&
            selectedProfileServer == selection.profile.server &&
            selectedProfileRawLink == selection.profile.rawLink &&
            selectedProfileJson == LocationConfigs.encodeStoredLocation(selection.profile) &&
            runtimeConfigJson == selection.runtimeConfigJson &&
            selectedProfileSourceUrl == selection.sourceUrl &&
            managementProxyPort == (selection.managementProxyPort?.takeIf { it in 1..65535 } ?: 0) &&
            lastBenchmarkSummary == selection.benchmark.detail
}
