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
    private val rollbackSelectionChange: suspend (previousState: PersistedState, baseMessage: String) -> String,
    private val stopConnection: suspend () -> Result<Unit>,
    private val updateLocationBenchmarkDetails: suspend (Map<String, String>) -> Unit,
    private val appendLatencyHistory: suspend (LatencyHistoryEntry) -> Unit,
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
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
        var lastFailureMessage: String? = plan.failureMessage
        for ((index, attempt) in plan.attempts.withIndex()) {
            updateStatus(
                BenchmarkStatusMessages.tryingBestCandidate(
                    attempt = index + 1,
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
            val verificationBenchmark = verifyActiveSelection(attempt).getOrElse { error ->
                BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                    candidate = attempt.preflight,
                    reason = error.message ?: "active_verification_failed",
                    secondaryStatus = "error",
                )
            }
            recordBenchmark(verificationBenchmark, benchmarkDetails)
            if (verificationBenchmark.secondaryStatus == "ok") {
                val verifiedSelection = attempt.selection.copy(benchmark = verificationBenchmark)
                val persistResult = runCatching {
                    persistSelection(verifiedSelection)
                }
                if (persistResult.isFailure) {
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
            updateStatus(BenchmarkStatusMessages.switchingAfterVerificationFailure(attempt.selection.profile.remarks))
            val stopResult = stopConnection()
            if (stopResult.isFailure) {
                return ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                    prefix = BenchmarkStatusMessages.switchingAfterVerificationFailure(attempt.selection.profile.remarks),
                    appMode = stateProvider().appMode,
                    errorMessage = stopResult.exceptionOrNull()?.message,
                )
            }
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
}
