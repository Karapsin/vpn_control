package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSelection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal class AndroidConnectionLifecycleService(
    private val stateProvider: () -> MainUiState,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val snapshot: suspend () -> PersistedState,
    private val restoreSnapshot: suspend (PersistedState, Boolean) -> Unit,
    private val ensureSelection: suspend () -> Result<ProfileSelection>,
    private val persistSelection: suspend (ProfileSelection) -> Unit,
    private val rehydrateSelection: suspend (PersistedState) -> Result<ProfileSelection>,
    private val startConnection: suspend (ProfileSelection) -> Result<Unit>,
    private val stopConnection: suspend () -> Result<Unit>,
) {
    suspend fun toggleConnection() {
        if (stateProvider().isVpnRunning) {
            stopCurrentConnection()
            return
        }

        val preconditionError = ConnectionOrchestrationLogic.toggleStartPreconditionError(stateProvider())
        if (preconditionError != null) {
            updateStatus(preconditionError)
            return
        }

        startSelectedConnection()
    }

    suspend fun reapplyConnectionIfRunning(
        selection: ProfileSelection,
        statusMessage: String,
    ): Result<Unit> {
        if (!stateProvider().isVpnRunning) {
            return Result.success(Unit)
        }

        updateState { it.copy(isStartingVpn = true) }
        return try {
            updateStatus(statusMessage)
            startConnection(selection)
        } finally {
            updateState { it.copy(isStartingVpn = false) }
        }
    }

    suspend fun startAndPersistSelection(
        selection: ProfileSelection,
        statusMessage: String,
    ): SelectionCommitResult {
        updateState { it.copy(isStartingVpn = true) }
        return try {
            updateStatus(statusMessage)
            val startResult = startConnection(selection)
            if (startResult.isFailure) {
                return SelectionCommitResult(
                    stage = SelectionCommitStage.APPLY_FAILED,
                    error = startResult.exceptionOrNull(),
                )
            }
            val persistResult = runCatching {
                persistSelection(selection)
            }
            if (persistResult.isFailure) {
                return SelectionCommitResult(
                    stage = SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY,
                    error = persistResult.exceptionOrNull(),
                )
            }
            SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
        } finally {
            updateState { it.copy(isStartingVpn = false) }
        }
    }

    suspend fun applyAndPersistSelection(
        selection: ProfileSelection,
        statusMessage: String,
    ): SelectionCommitResult {
        val connectionWasRunning = stateProvider().isVpnRunning
        val applyResult = reapplyConnectionIfRunning(
            selection = selection,
            statusMessage = statusMessage,
        )
        if (applyResult.isFailure) {
            return SelectionCommitResult(
                stage = SelectionCommitStage.APPLY_FAILED,
                error = applyResult.exceptionOrNull(),
            )
        }
        val persistResult = runCatching {
            persistSelection(selection)
        }
        if (persistResult.isFailure) {
            return SelectionCommitResult(
                stage = if (connectionWasRunning) {
                    SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY
                } else {
                    SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY
                },
                error = persistResult.exceptionOrNull(),
            )
        }
        return SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
    }

    suspend fun rollbackSelectionChange(
        previousState: PersistedState,
        baseMessage: String,
    ): String {
        val restoredSelection = rehydrateSelection(previousState)
        if (restoredSelection.isSuccess) {
            val restartResult = startConnection(restoredSelection.getOrThrow())
            return restartResult.fold(
                onSuccess = {
                    restoreSnapshot(previousState, false)
                    if (baseMessage == BenchmarkStatusMessages.locationSearchCancelled()) {
                        ConnectionStatusMessages.previousConnectionRestored(stateProvider().appMode)
                    } else {
                        ConnectionStatusMessages.previousConnectionRestoredWithReason(stateProvider().appMode, baseMessage)
                    }
                },
                onFailure = { restartError ->
                    val stopResult = stopConnection()
                    stopResult.fold(
                        onSuccess = {
                            restoreSnapshot(previousState, true)
                            ConnectionStatusMessages.previousConnectionRestoreFailedStopped(
                                stateProvider().appMode,
                                restartError.message.orEmpty(),
                            )
                        },
                        onFailure = { stopError ->
                            ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(
                                stateProvider().appMode,
                                restartError.message.orEmpty(),
                                stopError.message.orEmpty(),
                            )
                        },
                    )
                },
            )
        }

        val stopResult = stopConnection()
        return stopResult.fold(
            onSuccess = {
                restoreSnapshot(previousState, true)
                ConnectionStatusMessages.connectionStoppedKeepStateConsistent(stateProvider().appMode)
            },
            onFailure = { error ->
                ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(
                    stateProvider().appMode,
                    baseMessage,
                    error.message.orEmpty(),
                )
            },
        )
    }

    suspend fun rollbackStartedConnectionAfterPersistFailure(
        previousState: PersistedState,
        error: Throwable,
    ): String {
        val baseMessage = error.message ?: ConnectionStatusMessages.selectedLocationSaveFailed()
        val stopResult = stopConnection()
        return stopResult.fold(
            onSuccess = {
                restoreSnapshot(previousState, true)
                ConnectionStatusMessages.connectionStoppedKeepStateConsistent(stateProvider().appMode)
            },
            onFailure = { stopError ->
                ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(
                    stateProvider().appMode,
                    baseMessage,
                    stopError.message.orEmpty(),
                )
            },
        )
    }

    private suspend fun stopCurrentConnection() {
        setBusy(true)
        try {
            val result = stopConnection()
            updateStatus(
                result.fold(
                    onSuccess = { MainCommandLogic.stoppedConnectionStatus(stateProvider().appMode) },
                    onFailure = {
                        ConnectionOrchestrationLogic.connectionStopFailureMessage(
                            appMode = stateProvider().appMode,
                            errorMessage = it.message,
                        )
                    },
                ),
            )
        } catch (_: CancellationException) {
            withContext(NonCancellable) {
                updateStatus(
                    ConnectionOrchestrationLogic.connectionStopCancelledMessage(
                        stateProvider().appMode,
                    ),
                )
            }
        } finally {
            setBusy(false)
        }
    }

    private suspend fun startSelectedConnection() {
        setBusy(true)
        val previousState = snapshot()
        var startAttempted = false
        try {
            updateStatus(
                ConnectionOrchestrationLogic.preparingConnectionMessage(stateProvider().appMode),
            )

            val selection = ensureSelection()
            if (selection.isFailure) {
                updateStatus(
                    ConnectionOrchestrationLogic.ensureSelectionFailureMessage(
                        appMode = stateProvider().appMode,
                        errorMessage = selection.exceptionOrNull()?.message,
                    ),
                )
                return
            }

            startAttempted = true
            val applyResult = startAndPersistSelection(
                selection = selection.getOrThrow(),
                statusMessage = MainCommandLogic.startingConnectionLabel(stateProvider().appMode),
            )
            val message = if (applyResult.isSuccess) {
                MainCommandLogic.startedConnectionStatus(stateProvider().appMode)
            } else {
                ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                    result = applyResult,
                    texts = ConnectionOrchestrationLogic.startSelectionFailureTexts(
                        stateProvider().appMode,
                    ),
                ).let { failureMessage ->
                    if (applyResult.requiresLiveRollback) {
                        rollbackStartedConnectionAfterPersistFailure(
                            previousState = previousState,
                            applyResult.error ?: IllegalStateException(failureMessage),
                        )
                    } else if (applyResult.shouldRestoreSnapshot) {
                        restoreSnapshot(previousState, true)
                        failureMessage
                    } else {
                        failureMessage
                    }
                }
            }
            updateStatus(message)
        } catch (_: CancellationException) {
            withContext(NonCancellable) {
                if (startAttempted) {
                    val stopResult = stopConnection()
                    updateStatus(
                        stopResult.fold(
                            onSuccess = {
                                restoreSnapshot(previousState, true)
                                ConnectionOrchestrationLogic.connectionStartCancelledMessage(
                                    stateProvider().appMode,
                                )
                            },
                            onFailure = {
                                ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                                    prefix = "${ConnectionOrchestrationLogic.connectionStartCancelledMessage(stateProvider().appMode)}.",
                                    appMode = stateProvider().appMode,
                                    errorMessage = it.message,
                                )
                            },
                        ),
                    )
                } else {
                    updateStatus(
                        ConnectionOrchestrationLogic.connectionStartCancelledMessage(
                            stateProvider().appMode,
                        ),
                    )
                }
            }
        } finally {
            setBusy(false)
        }
    }
}
