package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.StatusMessages
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
    private val refreshBestProfile: suspend () -> Result<ProfileSelection>,
    private val startAndPersistSelection: suspend (selection: ProfileSelection, statusMessage: String) -> SelectionCommitResult,
    private val rollbackSelectionChange: suspend (previousState: PersistedState, baseMessage: String) -> String,
    private val stopConnection: suspend () -> Result<Unit>,
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
            val result = findBestProfileWithRetries()
            val message = result.fold(
                onSuccess = { selection ->
                    startAttempted = true
                    val applyResult = startAndPersistSelection(
                        selection,
                        MainCommandLogic.bestSelectionStartMessage(stateProvider().appMode),
                    )
                    if (applyResult.isSuccess) {
                        appendLatencyHistory(selection.benchmark)
                        ConnectionOrchestrationLogic.refreshSelectionStartedMessage(
                            appMode = stateProvider().appMode,
                            remarks = selection.profile.remarks,
                        )
                    } else if (applyResult.requiresLiveRollback) {
                        rollbackSelectionChange(
                            previousState,
                            ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                                result = applyResult,
                                texts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(
                                    stateProvider().appMode,
                                ),
                            ),
                        )
                    } else {
                        if (applyResult.shouldRestoreSnapshot) {
                            restoreSnapshot(previousState)
                        }
                        ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                            result = applyResult,
                            texts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(
                                stateProvider().appMode,
                            ),
                        )
                    }
                },
                onFailure = { error ->
                    error.message ?: StatusMessages.locationSearchFailed()
                },
            )
            updateStatus(message)
        } catch (_: CancellationException) {
            withContext(NonCancellable) {
                val message = when {
                    startAttempted && previousState.isVpnRunning ->
                        rollbackSelectionChange(previousState, "Location search cancelled.")
                    startAttempted -> {
                        val stopResult = stopConnection()
                        stopResult.fold(
                            onSuccess = {
                                restoreSnapshot(previousState)
                                ConnectionOrchestrationLogic.refreshCancelledMessage()
                            },
                            onFailure = {
                                ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                                    prefix = "Location search cancelled.",
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

    private suspend fun findBestProfileWithRetries(): Result<ProfileSelection> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = stateProvider().validationSettings.retryCount,
            onRetryStatus = { message -> updateStatus(message) },
            action = refreshBestProfile,
        )
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
