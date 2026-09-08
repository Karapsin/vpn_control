package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.SubscriptionRefreshBatchResult
import com.kardinal.vpncontrol.data.SubscriptionRefreshFailure
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

internal object AndroidRefreshCommitPolicy {
    fun deleteArtifacts(knowledge: AndroidRuntimeKnowledge): Boolean = knowledge == AndroidRuntimeKnowledge.STOPPED
    fun selectedMissing(before: PersistedState, subscriptions: List<SubscriptionSource>): Boolean {
        if (before.profileSourceMode != ProfileSourceMode.SUBSCRIPTION) return false
        val all = isAllSubscriptionsGroupActive(before.activeSubscriptionId, subscriptions)
        val relevant = if (all) subscriptions else subscriptions.filter { it.id == before.activeSubscriptionId }
        val selected = com.kardinal.vpncontrol.data.LocationConfigs.selectedStoredReference(before.selectedProfileJson, before.selectedProfileRawLink)
        return selected.isNotBlank() && selected !in mergedSubscriptionLocations(relevant) &&
            (all || relevant.any { it.url == before.selectedProfileSourceUrl })
    }
}
internal data class AndroidRefreshLoad(val source: SubscriptionSource, val locations: List<String>?, val code: ControlCode)
internal typealias AndroidRefreshContinuation = suspend (PersistedState, SubscriptionRefreshBatchResult, AndroidRuntimeRestorePoint?) -> List<String>

/** One owner lease spans cancellable loading and an indivisible commit/recovery boundary. */
internal class AndroidSubscriptionRefreshControl(
    private val controllerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val fetch: suspend (SubscriptionSource, PersistedState) -> List<String>,
    private val commit: suspend (List<AndroidRefreshLoad>, String, Long) -> ControlCommitted<PersistedState>,
    private val pending: (PersistedState) -> Boolean?,
    private val schedule: suspend (PersistedState, Boolean) -> Unit,
    private val capture: () -> AndroidRuntimeRestorePoint? = { null },
    private val prepareFetch: (suspend (PersistedState, AndroidRuntimeRestorePoint?) -> suspend (SubscriptionSource) -> List<String>)? = null,
) {
    private val fetches = mutableMapOf<String, Job>()
    fun cancel(operationId: String) = synchronized(fetches) { fetches[operationId]?.cancel() }

    suspend fun execute(request: ControlRequest, operationId: String,
        progress: (Long, Long) -> Unit, beginCommit: () -> Boolean, canFetch: () -> Boolean = { true },
        continuation: AndroidRefreshContinuation? = null,
    ): ControlResult {
        var actual: AndroidRuntimeRestorePoint? = null
        var durable: ControlCommitted<PersistedState>? = null
        var loaded = emptyList<AndroidRefreshLoad>()
        var saved = false
        var attemptAdmitted = false
        var scheduled = false
        var targetSources = emptyList<SubscriptionSource>()
        val staged = java.util.concurrent.ConcurrentHashMap<String, AndroidRefreshLoad>()
        fun result(code: ControlCode, warnings: List<String> = emptyList()): ControlResult {
            val restart = durable?.value?.let(pending)
            return ControlResult(controllerId, request.requestId, code, durable?.revision ?: 0, operationId = operationId,
                restartRequired = restart ?: false,
                warnings = warnings + (if (restart == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList()) +
                    if (durable == null) listOf("CONFIGURATION_REVISION_UNAVAILABLE") else emptyList(),
                data = mapOf("committed" to ControlValue.BooleanValue(saved),
                    "refreshedCount" to ControlValue.IntegerValue(if (saved) loaded.count { it.code == ControlCode.OK }.toLong() else 0),
                    "failedCount" to ControlValue.IntegerValue(loaded.count { it.code !in setOf(ControlCode.OK, ControlCode.CANCELLED) }.toLong()),
                    "cancelledCount" to ControlValue.IntegerValue(loaded.count { it.code == ControlCode.CANCELLED }.toLong()),
                    "subscriptions" to ControlValue.ArrayValue(loaded.map { load -> ControlValue.ObjectValue(mapOf(
                        "id" to ControlValue.Text(load.source.id), "code" to ControlValue.Text(load.code.wireName),
                        "committed" to ControlValue.BooleanValue(saved && load.code == ControlCode.OK),
                        "locationCount" to (load.locations?.size?.toLong()?.let(ControlValue::IntegerValue) ?: ControlValue.Null))) })))
        }
        suspend fun terminal(code: ControlCode, warnings: List<String> = emptyList()): ControlResult = withContext(NonCancellable) {
            var finalWarnings = warnings
            if (continuation != null && attemptAdmitted && !scheduled) {
                scheduled = true
                try { schedule(snapshot().value, true) } catch (_: Exception) { finalWarnings += "REFRESH_SCHEDULING_FAILED" }
            }
            result(code, finalWarnings)
        }
        try {
            val before = snapshot().also { durable = it }
            actual = capture()
            if (request.controllerId != controllerId || before.controllerId != controllerId ||
                request.ifRevision != null && request.ifRevision != before.revision) return result(ControlCode.CONFLICT)
            val sources = targets(before.value, (request.command.arguments.getValue("id") as ControlValue.Text).value)
            targetSources = sources
            // A valid scheduled attempt must arrange its successor even if route preparation fails.
            // Epoch/revision rejection above remains completely effect-free.
            attemptAdmitted = true
            val fetchCaptured: suspend (SubscriptionSource) -> List<String> =
                if (prepareFetch != null) prepareFetch.invoke(before.value, actual) else { source -> fetch(source, before.value) }
            progress(0, sources.size.toLong())
            loaded = supervisorScope {
                val worker = async(start = CoroutineStart.LAZY) {
                    val semaphore = Semaphore(before.value.validationSettings.normalized().subscriptionRefreshConcurrency.coerceAtLeast(1))
                    val completed = java.util.concurrent.atomic.AtomicLong()
                    sources.map { source -> async {
                        semaphore.withPermit {
                            val item = try {
                                val locations = fetchCaptured(source)
                                require(locations.isNotEmpty())
                                AndroidRefreshLoad(source, locations, ControlCode.OK)
                            } catch (cancel: CancellationException) { throw cancel }
                            catch (_: Exception) { AndroidRefreshLoad(source, null, ControlCode.RUNTIME_FAILED) }
                            staged[source.id] = item
                            progress(completed.incrementAndGet(), sources.size.toLong())
                            item
                        }
                    } }.awaitAll()
                }
                synchronized(fetches) { fetches[operationId] = worker }
                try { if (!canFetch()) worker.cancel(); worker.start(); worker.await() } finally { synchronized(fetches) { fetches.remove(operationId) } }
            }
            if (!beginCommit()) return terminal(ControlCode.CANCELLED, listOf("REFRESH_NOT_COMMITTED"))
            return withContext(NonCancellable) {
                durable = commit(loaded, controllerId, before.revision)
                saved = true
                val warnings = mutableListOf<String>()
                val batch = SubscriptionRefreshBatchResult(loaded.count { it.code == ControlCode.OK }, loaded.filter { it.code != ControlCode.OK }.map {
                    SubscriptionRefreshFailure(it.source.id, it.source.url, it.source.customName, it.code.wireName)
                })
                if (continuation != null) {
                    try { warnings += continuation(before.value, batch, actual); durable = snapshot() }
                    catch (_: Exception) { warnings += "REFRESH_RUNTIME_RECOVERY_FAILED"; durable = snapshot() }
                }
                scheduled = true
                try { schedule(requireNotNull(durable).value, continuation != null) } catch (_: Exception) { warnings += "REFRESH_SCHEDULING_FAILED" }
                result(if (loaded.any { it.code != ControlCode.OK } || warnings.isNotEmpty()) ControlCode.RUNTIME_FAILED else ControlCode.OK,
                    warnings + if (batch.hasFailures && batch.refreshedCount > 0) listOf("PARTIAL_REFRESH") else emptyList())
            }
        } catch (_: CancellationException) {
            loaded = targetSources.map { staged[it.id] ?: AndroidRefreshLoad(it, null, ControlCode.CANCELLED) }
            return terminal(ControlCode.CANCELLED, listOf(if (saved) "REFRESH_COMMITTED" else "REFRESH_NOT_COMMITTED"))
        }
        catch (error: Exception) { return terminal(when (error.message) {
            "CONFLICT" -> ControlCode.CONFLICT; "NOT_FOUND" -> ControlCode.NOT_FOUND; "INVALID_ARGUMENT" -> ControlCode.INVALID_ARGUMENT
            "RUNTIME_STATE_UNKNOWN", "RUNTIME_COMMAND_STALE", "ACTIVE_MANAGEMENT_ROUTE_UNAVAILABLE" -> ControlCode.RUNTIME_FAILED
            else -> ControlCode.PERSISTENCE_FAILED
        }, listOf(if (saved) "REFRESH_COMMITTED" else "REFRESH_NOT_COMMITTED")) }
        finally { actual?.close() }
    }

    companion object {
        fun arguments(values: Map<String, ControlValue>): Map<String, ControlValue> {
            require(values.keys == setOf("id") && (values["id"] as? ControlValue.Text)?.value?.isNotBlank() == true) { "INVALID_ARGUMENT" }
            return values
        }
        fun targets(state: PersistedState, id: String): List<SubscriptionSource> {
            val effective = if (id == "active") state.activeSubscriptionId else id
            val selected = if (effective == "all" || effective == ALL_SUBSCRIPTIONS_ID) state.subscriptions
                else state.subscriptions.filter { it.id == effective }
            require(selected.isNotEmpty()) { "NOT_FOUND" }
            return selected
        }
    }
}
