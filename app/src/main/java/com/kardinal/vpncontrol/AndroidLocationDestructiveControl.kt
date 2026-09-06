package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import java.util.Locale

/** Owner lease spans plan, acknowledged stop, commit and recovery; storage never owns native IO. */
internal class AndroidLocationDestructiveControl(
    private val controllerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val observation: () -> AndroidRuntimeObservation,
    private val capture: () -> AndroidRuntimeRestorePoint?,
    private val stop: suspend (AndroidRuntimeObservation) -> Result<Unit>,
    private val commit: suspend (AndroidLocationPlan, String, Long, AndroidRuntimeObservation) -> AndroidSettingsCommit,
    private val restore: suspend (AndroidRuntimeRestorePoint, AndroidRuntimeObservation) -> Result<Unit>,
    private val pendingRestart: (PersistedState) -> Boolean?,
) {
    suspend fun execute(request: ControlRequest, operationId: String): ControlResult =
        kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { perform(request, operationId) }

    private suspend fun perform(request: ControlRequest, operationId: String): ControlResult {
        var committed: ControlCommitted<PersistedState>? = null
        suspend fun result(code: ControlCode, warnings: List<String> = emptyList(), data: Map<String, ControlValue> = emptyMap()): ControlResult {
            // Failure/recovery can interleave a newer legacy save. Never report its older revision.
            val actual = if (code == ControlCode.OK) committed else runCatching { snapshot() }.getOrNull()
            val pending = actual?.let { pendingRestart(it.value) }
            return ControlResult(controllerId, request.requestId, code, actual?.revision ?: 0, operationId = operationId,
                restartRequired = pending ?: false, data = if (code == ControlCode.OK) data else emptyMap(),
                warnings = warnings + (if (pending == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()) +
                    (if (actual == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()))
        }
        committed = runCatching { snapshot() }.getOrNull() ?: return result(ControlCode.PERSISTENCE_FAILED)
        val before = committed
        if (request.controllerId != controllerId || before.controllerId != controllerId ||
            request.ifRevision != null && request.ifRevision != before.revision) return result(ControlCode.CONFLICT)
        val plan = runCatching { AndroidLocationControl.plan(before.value, request.command.operation, request.command.arguments,
            controllerId, AppStrings(before.value.appLanguage.effective(Locale.getDefault().language))) }
            .getOrElse { return result(code(it)) }
        val observed = observation()
        if (observed.knowledge == AndroidRuntimeKnowledge.UNKNOWN) return result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_NOT_CHANGED", "RUNTIME_OUTCOME_UNKNOWN"))
        val point = if (observed.knowledge == AndroidRuntimeKnowledge.RUNNING) capture() else null
        if (observed.knowledge == AndroidRuntimeKnowledge.RUNNING && (point == null || point.observation != observed))
            return result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_NOT_CHANGED", "RUNTIME_OUTCOME_UNKNOWN"))
        fun removed(raw: String, source: String): Boolean = source.isBlank() &&
            before.value.currentLocations.any { LocationConfigs.normalizeStoredReference(it) == LocationConfigs.normalizeStoredReference(raw) } &&
            requireNotNull(plan.locations).none { LocationConfigs.normalizeStoredReference(it) == LocationConfigs.normalizeStoredReference(raw) }
        val mustStop = point != null && removed(point.configuration.locationReference, point.configuration.sourceReference)
        var expected = observed
        if (mustStop) {
            val stopped = runCatching { stop(observed).getOrThrow() }
            if (stopped.isFailure) {
                val error = stopped.exceptionOrNull()
                val uncertain = error is kotlinx.coroutines.CancellationException || error is AndroidRuntimeOutcomeUnknownException ||
                    (error as? VpnCommandException)?.outcomeUnknown == true
                return result(ControlCode.RUNTIME_FAILED,
                    if (!uncertain && observation() == observed) listOf("RUNTIME_NOT_CHANGED") else listOf("RUNTIME_OUTCOME_UNKNOWN"))
            }
            expected = observation()
            if (expected.knowledge != AndroidRuntimeKnowledge.STOPPED) return result(ControlCode.RUNTIME_FAILED, listOf("RUNTIME_OUTCOME_UNKNOWN"))
        }
        val saved = runCatching { commit(plan, controllerId, before.revision, expected) }
        if (saved.isSuccess) {
            committed = saved.getOrThrow().committed
            return result(ControlCode.OK, data = if (request.command.operation == ControlOperationId.LOCATIONS_DELETE)
                mapOf("id" to ControlValue.Text(plan.id)) else mapOf("importedLocations" to ControlValue.IntegerValue(requireNotNull(plan.locations).size.toLong())))
        }
        if (!mustStop) return result(code(requireNotNull(saved.exceptionOrNull())))
        val recovered = if (observation() == expected) runCatching { restore(requireNotNull(point), expected).getOrThrow() } else Result.failure(IllegalStateException("RUNTIME_COMMAND_STALE"))
        val restored = capture()
        val exact = recovered.isSuccess && restored != null && restored.runtimeJson == point?.runtimeJson && restored.configuration == point.configuration
        return result(if (exact) code(requireNotNull(saved.exceptionOrNull())) else ControlCode.RUNTIME_FAILED,
            listOf(if (exact) "RUNTIME_RESTORED" else if (observation().knowledge == AndroidRuntimeKnowledge.STOPPED) "RUNTIME_STOPPED" else "RUNTIME_OUTCOME_UNKNOWN"))
    }

    private fun code(error: Throwable): ControlCode = when (error.message) {
        "CONFLICT" -> ControlCode.CONFLICT
        "NOT_FOUND" -> ControlCode.NOT_FOUND
        "AMBIGUOUS_LOCATION" -> ControlCode.AMBIGUOUS_LOCATION
        "INVALID_ARGUMENT" -> ControlCode.INVALID_ARGUMENT
        "UNSUPPORTED" -> ControlCode.UNSUPPORTED
        "RUNTIME_COMMAND_STALE", "RUNTIME_STATE_UNKNOWN" -> ControlCode.RUNTIME_FAILED
        else -> ControlCode.PERSISTENCE_FAILED
    }
}
