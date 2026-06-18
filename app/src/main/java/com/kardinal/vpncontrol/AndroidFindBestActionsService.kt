package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.data.BenchmarkSearchLogic
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.ProfileSelectionAttempt
import com.kardinal.vpncontrol.data.ProfileSelectionAttemptPlan
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal class AndroidFindBestActionsService(
    private val stateProvider: () -> MainUiState,
    private val launchTrackedBusyOperation: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val setRefreshing: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val snapshot: suspend () -> PersistedState,
    private val restoreSnapshot: suspend (PersistedState) -> Unit,
    private val refreshBestProfileAttemptPlan: suspend () -> Result<ProfileSelectionAttemptPlan>,
    private val startSelection: suspend (selection: ProfileSelection, statusMessage: String) -> SelectionCommitResult,
    private val persistSelection: suspend (selection: ProfileSelection) -> Unit,
    private val verifyActiveSelection: suspend (attempt: ProfileSelectionAttempt) -> Result<ProfileBenchmark>,
    private val verifySelectionCandidate: suspend (attempt: ProfileSelectionAttempt, attemptIndex: Int) -> Result<ProfileBenchmark>,
    private val rollbackSelectionChange: suspend (previousState: PersistedState, baseMessage: String) -> String,
    private val stopConnection: suspend () -> Result<Unit>,
    private val updateLocationBenchmarkDetails: suspend (Map<String, String>) -> Unit,
    private val appendLatencyHistory: suspend (LatencyHistoryEntry) -> Unit,
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
    private val diagnosticsLogger: (String) -> Unit = {},
) {
    fun refresh() {
        launchTrackedBusyOperation {
            refreshBestLocation()
        }
    }

    private suspend fun refreshBestLocation() {
        val preconditionError = MainCommandLogic.refreshPreconditionError(stateProvider())
        if (preconditionError != null) {
            updateStatus(preconditionError)
            return
        }
        setBusy(true)
        setRefreshing(true)
        val previousState = snapshot()
        var startAttempted = false
        try {
            updateStatus(MainCommandLogic.refreshStartStatus(stateProvider()))
            val message = runAttemptPlan(previousState) { startAttempted = true }
            updateStatus(message)
        } catch (_: CancellationException) {
            withContext(NonCancellable) {
                val message = when {
                    startAttempted && previousState.isVpnRunning ->
                        rollbackSelectionChange(previousState, BenchmarkStatusMessages.locationSearchCancelled())
                    startAttempted -> {
                        val stopResult = stopConnection()
                        stopResult.fold(
                            onSuccess = {
                                restoreSnapshot(previousState)
                                ConnectionOrchestrationLogic.refreshCancelledMessage()
                            },
                            onFailure = {
                                ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                                    prefix = BenchmarkStatusMessages.locationSearchCancelled(),
                                    appMode = stateProvider().appMode,
                                    errorMessage = it.message,
                                )
                            },
                        )
                    }
                    else -> ConnectionOrchestrationLogic.refreshCancelledMessage()
                }
                updateStatus(message)
            }
        } finally {
            setRefreshing(false)
            setBusy(false)
        }
    }

    private suspend fun runAttemptPlan(
        previousState: PersistedState,
        markStartAttempted: () -> Unit,
    ): String {
        val result = findBestProfileWithRetries()
        if (result.isFailure) {
            return result.exceptionOrNull()?.message ?: BenchmarkStatusMessages.locationSearchFailed()
        }
        val plan = result.getOrThrow()
        if (plan.attempts.isEmpty()) {
            return plan.failureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound()
        }

        val benchmarkDetails = plan.locationBenchmarkDetails.toMutableMap()
        val candidateBenchmarks = mutableMapOf<String, ProfileBenchmark>()
        val verificationWindowSize = stateProvider().validationSettings.normalized().activeVerificationWindowSize
        var lastFailureMessage: String? = plan.failureMessage
        var currentIndex = 0
        while (currentIndex < plan.attempts.size) {
            val window = BenchmarkSearchLogic.activeVerificationWindow(
                attempts = plan.attempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            )
            updateStatus(
                BenchmarkStatusMessages.testingLocationsRange(
                    start = currentIndex + 1,
                    end = currentIndex + window.size,
                    total = plan.attempts.size,
                ),
            )
            val precheck = BenchmarkSearchLogic.validateCandidateWindowForBestPass(
                attempts = plan.attempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            ) { candidate, attemptIndex ->
                val rawKey = LocationConfigs.encodeStoredLocation(candidate.selection.profile)
                candidateBenchmarks[rawKey] ?: verifySelectionCandidate(candidate, attemptIndex)
                    .getOrElse { error ->
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = candidate.preflight,
                            reason = error.message ?: "candidate_verification_failed",
                            secondaryStatus = "error",
                        )
                    }
            }
            precheck.completed.forEach { result ->
                candidateBenchmarks[LocationConfigs.encodeStoredLocation(result.benchmark.profile)] = result.benchmark
                recordBenchmark(result.benchmark, benchmarkDetails)
            }
            val verifiedCandidates = precheck.verifiedCandidates
            if (verifiedCandidates.isEmpty()) {
                val skipSummary = BenchmarkSearchLogic.strictTargetSkipSummary(
                    precheck.completed.map { it.benchmark },
                )
                lastFailureMessage = skipSummary.ifBlank {
                    precheck.completed.lastOrNull()?.benchmark?.detail ?: lastFailureMessage
                }
                currentIndex += window.size.coerceAtLeast(1)
                continue
            }

            for (winner in verifiedCandidates) {
                val attempt = winner.attempt
                updateStatus(
                    BenchmarkStatusMessages.tryingBestCandidate(
                        attempt = winner.attemptIndex + 1,
                        total = plan.attempts.size,
                        remarks = attempt.selection.profile.remarks,
                    ),
                )
                markStartAttempted()
                val startResult = startSelection(
                    attempt.selection,
                    MainCommandLogic.bestSelectionStartMessage(stateProvider().appMode),
                )
                if (!startResult.isSuccess) {
                    if (startResult.shouldRestoreSnapshot) {
                        restoreSnapshot(previousState)
                    }
                    lastFailureMessage = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                        result = startResult,
                        texts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(stateProvider().appMode),
                    )
                    recordBenchmark(
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = attempt.preflight,
                            reason = lastFailureMessage,
                            secondaryStatus = "error",
                        ),
                        benchmarkDetails,
                    )
                    continue
                }

                updateStatus(BenchmarkStatusMessages.verifyingBlockedResource(attempt.selection.profile.remarks))
                val attemptRawKey = LocationConfigs.encodeStoredLocation(attempt.selection.profile)
                diagnosticsLogger(
                    "Find Best active verification begin: profile=${attempt.selection.profile.remarks} " +
                        "attempt=${winner.attemptIndex + 1}/${plan.attempts.size}",
                )
                val verificationBenchmark = verifyActiveSelection(attempt)
                    .getOrElse { error ->
                        diagnosticsLogger(
                            "Find Best active verification call failed: profile=${attempt.selection.profile.remarks} " +
                                "attempt=${winner.attemptIndex + 1}/${plan.attempts.size} " +
                                "error=${diagnosticsErrorSummary(error)}",
                        )
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = attempt.preflight,
                            reason = error.message ?: "active_verification_failed",
                            secondaryStatus = "error",
                        )
                    }
                candidateBenchmarks[attemptRawKey] = verificationBenchmark
                recordBenchmark(verificationBenchmark, benchmarkDetails)
                if (verificationBenchmark.testStatus == "ok") {
                    diagnosticsLogger(
                        "Find Best active verification accepted: profile=${attempt.selection.profile.remarks} " +
                            "attempt=${winner.attemptIndex + 1}/${plan.attempts.size} detail=${verificationBenchmark.detail}",
                    )
                    val verifiedSelection = attempt.selection.copy(benchmark = verificationBenchmark)
                    val persistResult = runCatching {
                        persistSelection(verifiedSelection)
                    }
                    if (persistResult.isFailure) {
                        diagnosticsLogger(
                            "Find Best verified selection persist failed: profile=${attempt.selection.profile.remarks} " +
                                "error=${diagnosticsErrorSummary(persistResult.exceptionOrNull())}",
                        )
                        return rollbackSelectionChange(
                            previousState,
                            persistResult.exceptionOrNull()?.message
                                ?: ConnectionStatusMessages.bestLocationStartedSaveFailed(stateProvider().appMode),
                        )
                    }
                    appendLatencyHistory(verificationBenchmark)
                    return ConnectionOrchestrationLogic.refreshSelectionStartedMessage(
                        appMode = stateProvider().appMode,
                        remarks = verifiedSelection.profile.remarks,
                    )
                }

                lastFailureMessage = verificationBenchmark.detail
                diagnosticsLogger(
                    "Find Best active verification rejected: profile=${attempt.selection.profile.remarks} " +
                        "attempt=${winner.attemptIndex + 1}/${plan.attempts.size} status=${verificationBenchmark.testStatus} " +
                        "detail=${verificationBenchmark.detail}",
                )
                updateStatus(BenchmarkStatusMessages.switchingAfterVerificationFailure(attempt.selection.profile.remarks))
                val stopResult = stopConnection()
                if (stopResult.isFailure) {
                    diagnosticsLogger(
                        "Find Best stop after verification failure failed: profile=${attempt.selection.profile.remarks} " +
                            "error=${diagnosticsErrorSummary(stopResult.exceptionOrNull())}",
                    )
                    return ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                        prefix = BenchmarkStatusMessages.switchingAfterVerificationFailure(
                            attempt.selection.profile.remarks,
                        ),
                        appMode = stateProvider().appMode,
                        errorMessage = stopResult.exceptionOrNull()?.message,
                    )
                }
            }
            currentIndex += window.size.coerceAtLeast(1)
        }

        return if (previousState.isVpnRunning) {
            val message = rollbackSelectionChange(
                previousState,
                lastFailureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound(),
            )
            updateLocationBenchmarkDetails(benchmarkDetails)
            message
        } else {
            val finalMessage = lastFailureMessage ?: BenchmarkStatusMessages.noSuitableLocationFound()
            stopConnection().fold(
                onSuccess = {
                    restoreSnapshot(previousState)
                    updateLocationBenchmarkDetails(benchmarkDetails)
                    finalMessage
                },
                onFailure = {
                    ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                        prefix = finalMessage,
                        appMode = stateProvider().appMode,
                        errorMessage = it.message,
                    )
                },
            )
        }
    }

    private suspend fun findBestProfileWithRetries(): Result<ProfileSelectionAttemptPlan> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = stateProvider().validationSettings.retryCount,
            onRetryStatus = { message -> updateStatus(message) },
            action = refreshBestProfileAttemptPlan,
        )
    }

    private suspend fun recordBenchmark(
        benchmark: ProfileBenchmark,
        benchmarkDetails: MutableMap<String, String>,
    ) {
        benchmarkDetails[LocationConfigs.encodeStoredLocation(benchmark.profile)] = benchmark.detail
        updateLocationBenchmarkDetails(benchmarkDetails)
        updateStatus(benchmark.detail)
    }

    private suspend fun appendLatencyHistory(benchmark: ProfileBenchmark) {
        appendLatencyHistory(
            LatencyHistoryEntry(
                id = idGenerator(),
                profileName = benchmark.profile.remarks,
                detail = benchmark.detail,
                primaryStatus = benchmark.primaryStatus,
                secondaryStatus = benchmark.secondaryStatus,
                primaryTotalMs = benchmark.primaryTotal,
                secondaryTotalMs = benchmark.secondaryTotal,
                createdAtEpochMillis = clockMillis(),
            ),
        )
    }

    private fun diagnosticsErrorSummary(error: Throwable?): String {
        if (error == null) return "Unknown"
        val message = error.message
            ?.replace(Regex("[\\r\\n]+"), " ")
            ?.take(180)
            ?.takeIf { it.isNotBlank() }
        return buildString {
            append(error.javaClass.simpleName)
            if (message != null) {
                append(": ")
                append(message)
            }
        }
    }

}
