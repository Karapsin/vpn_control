package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap

/** One admitted search; probes may cancel, native acknowledgments and recovery may not. */
internal class AndroidFindBestControl(
    private val ownerId: String,
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val pending: (PersistedState) -> Boolean?,
    private val prepareInteraction: suspend (ControlRequest, String, PersistedState, (Boolean) -> Boolean) -> ControlCode,
    private val openRuntime: suspend (PersistedState) -> Runtime,
    private val plan: suspend (PersistedState) -> Result<AndroidFindBestPlan>,
    private val probe: suspend (ProfileSelectionAttempt, Int) -> Result<ProfileBenchmark>,
    private val verify: suspend (ProfileSelectionAttempt) -> Result<ProfileBenchmark>,
    private val commit: suspend (ProfileSelection, String, Long, AndroidFindBestPlan) -> ControlCommitted<PersistedState>,
    private val cancelInteraction: (String) -> Unit,
    private val finishInteraction: (String) -> Unit = {},
) {
    interface Runtime {
        suspend fun start(selection: ProfileSelection): Result<Unit>
        suspend fun stopCandidate(): Result<Unit>
        suspend fun recover(): String
        suspend fun release(): Result<Unit>
    }
    private val probes = ConcurrentHashMap<String, Job>()
    fun cancel(id: String) { cancelInteraction(id); probes[id]?.cancel() }

    suspend fun execute(request: ControlRequest, id: String, progress: (Long, Long) -> Unit,
        awaitingUser: (Boolean) -> Boolean, canRun: () -> Boolean, beginCommit: () -> Boolean): ControlResult {
        var cleanupFailed = false
        val result = try { executeWithInteraction(request, id, progress, awaitingUser, canRun, beginCommit) }
        finally {
            try { finishInteraction(id) }
            catch (_: Exception) { cleanupFailed = true }
            catch (_: OutOfMemoryError) { cleanupFailed = true }
        }
        return if (cleanupFailed) result.copy(warnings = result.warnings + "INTERACTION_RELEASE_FAILED") else result
    }

    private suspend fun executeWithInteraction(request: ControlRequest, id: String, progress: (Long, Long) -> Unit,
        awaitingUser: (Boolean) -> Boolean, canRun: () -> Boolean, beginCommit: () -> Boolean): ControlResult {
        var metadata = snapshot()
        fun result(code: ControlCode, warnings: List<String> = emptyList(), committed: Boolean? = false): ControlResult {
            val restart = pending(metadata.value)
            return ControlResult(ownerId, request.requestId, code, metadata.revision, operationId = id,
                restartRequired = restart ?: false,
                data = mapOf("committed" to (committed?.let(ControlValue::BooleanValue) ?: ControlValue.Null)),
                warnings = warnings + if (restart == null) listOf("PENDING_RESTART_STATE_UNAVAILABLE") else emptyList())
        }
        if (request.controllerId != ownerId || metadata.controllerId != ownerId ||
            request.ifRevision != null && request.ifRevision != metadata.revision) return result(ControlCode.CONFLICT)
        if (!canRun()) return result(ControlCode.CANCELLED)
        val permission = prepareInteraction(request, id, metadata.value, awaitingUser)
        if (permission != ControlCode.OK) return result(permission)
        var runtime: Runtime? = null
        var succeeded = false
        var commitAttempt: ProfileSelection? = null
        var commitPlan: AndroidFindBestPlan? = null
        var commitUnknown = false
        var code = ControlCode.RUNTIME_FAILED
        val warnings = mutableListOf<String>()
        suspend fun reconcileFailure(error: Throwable) {
            if (error is OutOfMemoryError) warnings += "RESOURCE_EXHAUSTED"
            if (succeeded) {
                // The commit returned authoritative metadata before later presentation failed.
                code = ControlCode.OK
                warnings += "POST_COMMIT_RESULT_UNAVAILABLE"
                return
            }
            code = if (error is CancellationException) ControlCode.CANCELLED else ControlCode.RUNTIME_FAILED
            val selection = commitAttempt ?: return
            withContext(NonCancellable) {
                val observed = try {
                    val current = snapshot()
                    Triple(current,
                        current.controllerId == ownerId && commitPlan?.matchesCommittedSelection(current.value, selection) == true,
                        current.controllerId == ownerId && current.revision == metadata.revision &&
                            com.kardinal.vpncontrol.control.ControlConfigurationIdentity.of(current.value) ==
                            com.kardinal.vpncontrol.control.ControlConfigurationIdentity.of(metadata.value))
                } catch (_: Exception) { null } catch (_: OutOfMemoryError) { null }
                when {
                    observed?.second == true -> {
                        metadata = observed.first; succeeded = true; code = ControlCode.OK
                        warnings += "POST_COMMIT_RESULT_UNAVAILABLE"
                    }
                    observed?.third == true -> metadata = observed.first
                    else -> {
                        commitUnknown = true
                        code = ControlCode.OUTCOME_UNKNOWN
                        if (observed != null) metadata = observed.first else warnings += "CONFIGURATION_REVISION_UNAVAILABLE"
                        warnings += "CONFIGURATION_OUTCOME_UNKNOWN"
                    }
                }
            }
        }
        try {
            supervisorScope {
                val worker = async(start = CoroutineStart.LAZY) {
                    ensureActive()
                    check(canRun()) { "CANCELLED" }
                    // Capture actual A before planning. Pending B is never a recovery target.
                    runtime = openRuntime(metadata.value)
                    val prepared = ConnectionOrchestrationLogic.findBestProfileWithRetries(
                        retryCount = metadata.value.validationSettings.retryCount,
                        onRetryStatus = {}, action = { plan(metadata.value) }).getOrThrow()
                    val attempts = prepared.candidates
                    val details = attempts.locationBenchmarkDetails.toMutableMap()
                    val total = attempts.attempts.size.toLong()
                    progress(0, total)
                    var index = 0
                    while (index < attempts.attempts.size) {
                        ensureActive()
                        val checked = BenchmarkSearchLogic.validateCandidateWindowForBestPass(attempts.attempts, index,
                            metadata.value.validationSettings.normalized().activeVerificationWindowSize) { candidate, number ->
                            probe(candidate, number).getOrElse { error ->
                                if (error is CancellationException) throw error
                                BenchmarkSearchLogic.failedActiveVerificationBenchmark(candidate.preflight,
                                    "candidate_verification_failed", "error")
                            }
                        }
                        checked.completed.forEach { checkedCandidate ->
                            details[LocationConfigs.encodeStoredLocation(checkedCandidate.benchmark.profile)] = checkedCandidate.benchmark.detail
                        }
                        for (winner in checked.verifiedCandidates) {
                            ensureActive()
                            val attempt = winner.attempt
                            val started = withContext(NonCancellable) { requireNotNull(runtime).start(attempt.selection) }
                            ensureActive()
                            if (started.isFailure) throw requireNotNull(started.exceptionOrNull())
                            val verified = verify(attempt).getOrElse { error ->
                                if (error is CancellationException) throw error
                                BenchmarkSearchLogic.failedActiveVerificationBenchmark(attempt.preflight,
                                    "active_verification_failed", "error")
                            }
                            details[LocationConfigs.encodeStoredLocation(verified.profile)] = verified.detail
                            if (verified.testStatus == "ok") {
                                if (!beginCommit()) throw CancellationException("Search cancelled before commit")
                                withContext(NonCancellable) {
                                    commitAttempt = attempt.selection.copy(benchmark = verified)
                                    val finalPlan = prepared.copy(candidates = attempts.copy(locationBenchmarkDetails = details.toMap()))
                                    commitPlan = finalPlan
                                    metadata = commit(attempt.selection.copy(benchmark = verified), ownerId, metadata.revision, finalPlan)
                                    succeeded = true
                                    code = ControlCode.OK
                                    progress(total, total)
                                }
                                return@async
                            }
                            withContext(NonCancellable) { requireNotNull(runtime).stopCandidate().getOrThrow() }
                        }
                        index += metadata.value.validationSettings.normalized().activeVerificationWindowSize.coerceAtLeast(1)
                        progress(minOf(index.toLong(), total), total)
                    }
                }
                probes[id] = worker
                if (!canRun()) worker.cancel()
                worker.start()
                worker.await()
            }
        } catch (error: Exception) {
            reconcileFailure(error)
        } catch (error: OutOfMemoryError) {
            reconcileFailure(error)
        } finally {
            probes.remove(id)
            withContext(NonCancellable) {
                if (!succeeded && !commitUnknown) runtime?.let {
                    warnings += try { it.recover() } catch (_: Exception) { "RUNTIME_OUTCOME_UNKNOWN" }
                }
                runtime?.let { if (try { it.release().isFailure } catch (_: Exception) { true }) warnings += "RUNTIME_SERVICE_RELEASE_FAILED" }
            }
        }
        return result(code, warnings, if (commitUnknown) null else succeeded)
    }
}
