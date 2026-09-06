package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*

/** Runs only inside the owner's shared mutation lease. Never starts a service for an off no-op. */
internal class AndroidOffControl(
    private val controllerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val observation: () -> AndroidRuntimeObservation,
    private val stop: suspend () -> Result<Unit>,
    private val pendingRestart: (PersistedState) -> Boolean?,
) {
    fun available(): Boolean = observation().knowledge != AndroidRuntimeKnowledge.UNKNOWN

    suspend fun execute(request: ControlRequest, operationId: String): ControlResult {
        val committed = try { snapshot() } catch (_: Exception) {
            return ControlResult(controllerId, request.requestId, ControlCode.PERSISTENCE_FAILED, 0,
                operationId = operationId, warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE", "PENDING_RESTART_STATE_UNAVAILABLE"))
        }
        fun result(code: ControlCode, warnings: List<String> = emptyList()): ControlResult {
            val pending = pendingRestart(committed.value)
            return ControlResult(controllerId, request.requestId, code, committed.revision,
                operationId = operationId, restartRequired = pending ?: false,
                warnings = warnings + if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
        }
        if (request.controllerId != controllerId || committed.controllerId != controllerId ||
            request.ifRevision != null && request.ifRevision != committed.revision) return result(ControlCode.CONFLICT)
        when (observation().knowledge) {
            AndroidRuntimeKnowledge.STOPPED -> return result(ControlCode.OK)
            AndroidRuntimeKnowledge.UNKNOWN -> return result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_NOT_CHANGED", "RUNTIME_OUTCOME_UNKNOWN"))
            AndroidRuntimeKnowledge.RUNNING -> Unit
        }
        val stopped = runCatching { stop().getOrThrow() }
        if (stopped.isFailure) {
            val error = stopped.exceptionOrNull()
            val unknown = (error as? com.kardinal.vpncontrol.data.VpnCommandException)?.outcomeUnknown == true ||
                error is kotlinx.coroutines.CancellationException ||
                observation().knowledge == AndroidRuntimeKnowledge.UNKNOWN
            return result(ControlCode.RUNTIME_FAILED, if (unknown) listOf("RUNTIME_OUTCOME_UNKNOWN") else emptyList())
        }
        return if (observation().knowledge == AndroidRuntimeKnowledge.STOPPED) result(ControlCode.OK)
        else result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_OUTCOME_UNKNOWN"))
    }
}
