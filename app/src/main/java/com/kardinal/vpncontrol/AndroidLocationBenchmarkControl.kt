package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidLocationControl
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import kotlinx.coroutines.*

/** A single captured visible location; probing never selects or replaces the active runtime. */
internal class AndroidLocationBenchmarkControl(
    private val controllerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val probe: suspend (String, PersistedState) -> ProfileBenchmark,
    private val commit: suspend (String, ProfileBenchmark, String, Long) -> ControlCommitted<PersistedState>,
    private val pending: (PersistedState) -> Boolean?,
) {
    private val probes = mutableMapOf<String, Job>()
    fun cancel(operationId: String) = synchronized(probes) { probes[operationId]?.cancel() }

    suspend fun execute(request: ControlRequest, operationId: String, progress: (Long, Long) -> Unit,
        beginCommit: () -> Boolean, canProbe: () -> Boolean = { true },
    ): ControlResult {
        var captured: ControlCommitted<PersistedState>? = null
        var id: String? = null
        var committed = false
        var measuring = false
        var measured: ProfileBenchmark? = null
        fun result(code: ControlCode): ControlResult {
            val restart = captured?.value?.let(pending)
            fun timing(value: Double?): ControlValue = value?.takeIf { it.isFinite() && it >= 0 }
                ?.let(ControlValue::DecimalValue) ?: ControlValue.Null
            return ControlResult(controllerId, request.requestId, code, captured?.revision ?: 0,
                operationId = operationId, restartRequired = restart ?: false,
                warnings = (if (restart == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()) +
                    (if (captured == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList()),
                data = mapOf("committed" to ControlValue.BooleanValue(committed)) +
                    (id?.let { mapOf("id" to ControlValue.Text(it)) } ?: emptyMap()) +
                    if (committed) {
                        val committedMeasurement = requireNotNull(measured)
                        mapOf(
                            "primaryStatus" to ControlValue.Text(committedMeasurement.primaryStatus),
                            "secondaryStatus" to ControlValue.Text(committedMeasurement.secondaryStatus),
                            "primaryTotalMs" to timing(committedMeasurement.primaryTotal),
                            "secondaryTotalMs" to timing(committedMeasurement.secondaryTotal),
                        )
                    } else emptyMap())
        }
        try {
            val before = snapshot().also { captured = it }
            if (request.controllerId != controllerId || before.controllerId != controllerId ||
                request.ifRevision != null && request.ifRevision != before.revision) return result(ControlCode.CONFLICT)
            val raw = target(before.value, arguments(request.command.arguments), controllerId)
            id = AndroidLocationControl.identity(controllerId, before.value, raw)
            if (pending(before.value) == null) return result(ControlCode.RUNTIME_FAILED)
            progress(0, 1)
            measuring = true
            measured = supervisorScope {
                val task = async(start = CoroutineStart.LAZY) { probe(raw, before.value) }
                synchronized(probes) { probes[operationId] = task }
                try { if (!canProbe()) task.cancel(); task.start(); task.await() }
                finally { synchronized(probes) { probes.remove(operationId) } }
            }
            measuring = false
            if (!beginCommit()) return result(ControlCode.CANCELLED)
            return withContext(NonCancellable) {
                captured = commit(raw, requireNotNull(measured), controllerId, before.revision)
                committed = true
                progress(1, 1)
                result(if (measured?.testStatus == "ok") ControlCode.OK else ControlCode.RUNTIME_FAILED)
            }
        } catch (_: TimeoutCancellationException) { return result(ControlCode.RUNTIME_FAILED) }
        catch (_: CancellationException) { return result(ControlCode.CANCELLED) }
        catch (failure: Exception) {
            return result(when (failure) {
                is ControlProtocolException -> failure.code
                else -> when (failure.message) {
                    "CONFLICT" -> ControlCode.CONFLICT
                    "NOT_FOUND" -> ControlCode.NOT_FOUND
                    "INVALID_ARGUMENT" -> ControlCode.INVALID_ARGUMENT
                    else -> if (measuring || captured == null) ControlCode.RUNTIME_FAILED else ControlCode.PERSISTENCE_FAILED
                }
            })
        }
    }

    companion object {
        fun arguments(values: Map<String, ControlValue>): Map<String, ControlValue> {
            require(values.keys == setOf("selector") || values.keys == setOf("id")) { "INVALID_ARGUMENT" }
            require(values.values.all { it is ControlValue.Text && it.value.isNotBlank() }) { "INVALID_ARGUMENT" }
            return values
        }
        fun target(state: PersistedState, values: Map<String, ControlValue>, owner: String): String {
            val rows = androidLocationRows(MainUiStateProjector.mergePersistedState(MainUiState(), state),
                AppStrings(state.appLanguage.effective(java.util.Locale.getDefault().language)))
            (values["id"] as? ControlValue.Text)?.let { id ->
                return rows.singleOrNull { AndroidLocationControl.identity(owner, state, it.rawLink) == id.value }?.rawLink
                    ?: error("CONFLICT")
            }
            return when (val selected = ControlLocationSelection.resolve((values.getValue("selector") as ControlValue.Text).value, rows, { it.name })) {
                is ControlLocationResolution.Found -> selected.location.rawLink
                is ControlLocationResolution.Rejected -> throw ControlProtocolException(selected.code)
            }
        }
    }
}
