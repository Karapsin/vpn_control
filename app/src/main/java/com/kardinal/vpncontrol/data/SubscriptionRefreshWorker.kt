package com.kardinal.vpncontrol.data

import android.content.Context
import android.net.VpnService
import androidx.work.WorkManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.kardinal.vpncontrol.ConnectionOrchestrationLogic
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive

class SubscriptionRefreshWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    private val storage = ProfileStorage(appContext)

    override suspend fun doWork(): Result {
        val state = storage.snapshot()
        val subscriptionRefreshScheduler = SubscriptionRefreshScheduler(applicationContext)
        val refreshAll = isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION ||
            state.subscriptionRefreshPolicy == SubscriptionRefreshPolicy.OFF ||
            if (refreshAll) state.subscriptions.isEmpty() else state.profileUrl.isBlank()
        ) {
            WorkManager.getInstance(applicationContext)
                .cancelUniqueWork(SubscriptionRefreshScheduler.WORK_NAME)
            DiagnosticsLogger.append(
                applicationContext,
                "Background subscription sync skipped: mode=${state.profileSourceMode} policy=${state.subscriptionRefreshPolicy} urlSet=${state.profileUrl.isNotBlank()}",
            )
            return Result.success()
        }
        val hasValidSource = if (refreshAll) {
            state.subscriptions.any { subscription ->
                subscription.url.isNotBlank() &&
                    RemoteSourceResolver.validateProfileSource(subscription.url).isSuccess
            }
        } else {
            RemoteSourceResolver.validateProfileSource(state.profileUrl).isSuccess
        }
        if (!hasValidSource) {
            WorkManager.getInstance(applicationContext)
                .cancelUniqueWork(SubscriptionRefreshScheduler.WORK_NAME)
            DiagnosticsLogger.append(
                applicationContext,
                "Background subscription sync skipped: unsupported remote source",
            )
            return Result.success()
        }

        val orchestrator = BenchmarkOrchestrator(applicationContext, storage)
        val vpnManager = VpnManager(applicationContext, storage)
        val repository = AppRepository(
            storage = storage,
            orchestrator = orchestrator,
            subscriptionRefreshScheduler = subscriptionRefreshScheduler,
        )
        suspend fun finishAndScheduleNext(): Result {
            subscriptionRefreshScheduler.scheduleNext(storage.snapshot())
            return Result.success()
        }
        val previousSelectedStored = LocationConfigs.selectedStoredReference(
            selectedProfileJson = state.selectedProfileJson,
            selectedProfileRawLink = state.selectedProfileRawLink,
        )
        val refreshResult = if (refreshAll) {
            repository.refreshAllSubscriptionsCaches()
        } else {
            repository.refreshActiveSubscriptionCache()
        }
        return refreshResult.fold(
            onSuccess = { refresh ->
                val refreshedState = storage.snapshot()
                val failedSubscriptions = refresh.failedSubscriptions
                val failedSubscriptionNames = failedSubscriptions.map { it.displayName }
                val selectedSourceFailed = SubscriptionRefreshResultLogic.selectedSourceFailed(
                    selectedProfileSourceUrl = state.selectedProfileSourceUrl,
                    failures = failedSubscriptions,
                )
                val selectedMissing = SubscriptionRefreshResultLogic.selectedMissingAfterRefresh(
                    refreshAll = refreshAll,
                    previousState = state,
                    refreshedState = refreshedState,
                    previousSelectedStored = previousSelectedStored,
                )

                if (state.isVpnRunning && state.findBestAfterSubscriptionRefresh) {
                    if (state.appMode == AppMode.VPN && VpnService.prepare(applicationContext) != null) {
                        storage.restoreSelection(
                            state,
                            restoreRuntimeArtifacts = true,
                            sourceUrlOverride = "",
                        )
                        storage.updateStatus(StatusMessages.backgroundVpnPermissionRequiredKeepingPrevious())
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background subscription sync skipped auto-switch because VPN permission is not available in background",
                        )
                        return@fold finishAndScheduleNext()
                    }
                    storage.updateStatus(StatusMessages.backgroundRefreshFindingBest())
                    var switchFailure: Throwable? = null
                    val replacement = findBestProfileWithRetries(
                        orchestrator = orchestrator,
                        retryCount = state.validationSettings.retryCount,
                    )
                    if (replacement.isSuccess) {
                        val selection = replacement.getOrThrow()
                        val switchResult = startReplacementLocation(
                            selection = selection,
                            sourceUrl = selection.sourceUrl.ifBlank { state.profileUrl },
                            vpnManager = vpnManager,
                            repository = repository,
                        )
                        if (switchResult.isSuccess) {
                            val winnerSource = backgroundSelectionSourceLabel(
                                sourceUrl = selection.sourceUrl,
                                state = refreshedState,
                            )
                            storage.updateStatus(
                                SubscriptionRefreshResultLogic.backgroundSwitchedMessage(
                                    appMode = state.appMode,
                                    selectedProfileName = selection.profile.remarks,
                                    winnerSource = winnerSource,
                                    failedSubscriptionNames = failedSubscriptionNames,
                                ),
                            )
                            DiagnosticsLogger.append(
                                applicationContext,
                                "Background subscription sync switched ${connectionLabel(state.appMode)} to refreshed best location: ${selection.profile.remarks}" +
                                    (winnerSource?.let { " from $it" } ?: ""),
                            )
                            return@fold finishAndScheduleNext()
                        }
                        switchFailure = switchResult.exceptionOrNull()
                    }

                    val rollbackMessage = recoverAfterReplacementFailure(
                        previousState = state,
                        switchAttempted = switchFailure?.let(::didDispatchVpnSwitchAttempt) == true,
                        orchestrator = orchestrator,
                        vpnManager = vpnManager,
                    )
                    val failureMessage = switchFailure?.message
                        ?: replacement.exceptionOrNull()?.message
                        ?: StatusMessages.replacementLocationSearchFailed()
                    storage.updateStatus(
                        SubscriptionRefreshResultLogic.backgroundReplacementFailedMessage(
                            appMode = state.appMode,
                            failureMessage = failureMessage,
                            failedSubscriptionNames = failedSubscriptionNames,
                            selectedSourceFailed = selectedSourceFailed,
                            rollbackMessage = rollbackMessage,
                        ),
                    )
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background subscription sync could not switch to refreshed best location: $failureMessage",
                    )
                    return@fold finishAndScheduleNext()
                }

                if (selectedMissing && state.isVpnRunning) {
                    storage.restoreSelection(
                        state,
                        restoreRuntimeArtifacts = true,
                        sourceUrlOverride = "",
                    )
                    storage.updateStatus(
                        SubscriptionRefreshResultLogic.backgroundSelectedMissingMessage(
                            appMode = state.appMode,
                            failedSubscriptionNames = failedSubscriptionNames,
                        ),
                    )
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background subscription sync kept previous ${connectionLabel(state.appMode)} location as fallback after active subscription changed",
                    )
                    return@fold finishAndScheduleNext()
                }

                if (state.isVpnRunning) {
                    storage.updateStatus(
                        SubscriptionRefreshResultLogic.backgroundKeptCurrentMessage(
                            appMode = state.appMode,
                            failedSubscriptionNames = failedSubscriptionNames,
                            selectedSourceFailed = selectedSourceFailed,
                        ),
                    )
                }

                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync complete: refreshed=${refresh.refreshedCount} failed=${refresh.failedCount} selectedMissing=$selectedMissing refreshAll=$refreshAll",
                )
                finishAndScheduleNext()
            },
            onFailure = { error ->
                if (!refreshAll && state.activeSubscriptionId.isNotBlank()) {
                    storage.updateSubscriptionRefreshStatus(
                        subscriptionId = state.activeSubscriptionId,
                        status = error.message ?: StatusMessages.backgroundRefreshFailed(),
                    )
                }
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync failed: ${error.message ?: error::class.java.simpleName}",
                )
                finishAndScheduleNext()
            },
        )
    }

    private suspend fun findBestProfileWithRetries(
        orchestrator: BenchmarkOrchestrator,
        retryCount: Int,
    ): kotlin.Result<ProfileSelection> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = retryCount,
            onRetryStatus = storage::updateStatus,
            action = orchestrator::refreshBestProfile,
        )
    }

    private suspend fun startReplacementLocation(
        selection: ProfileSelection,
        sourceUrl: String,
        vpnManager: VpnManager,
        repository: AppRepository,
    ): kotlin.Result<Unit> {
        val appMode = storage.snapshot().appMode
        storage.updateStatus(StatusMessages.startingConnectionWithBestLocation(appMode))
        val startResult = vpnManager.start(selection)
        if (startResult.isFailure) {
            return kotlin.Result.failure(
                startResult.exceptionOrNull() ?: IllegalStateException(StatusMessages.bestLocationStartFailed(appMode)),
            )
        }
        val persistResult = runCatching {
            repository.persistSelection(selection, sourceUrl)
        }
        if (persistResult.isFailure) {
            return kotlin.Result.failure(
                persistResult.exceptionOrNull() ?: IllegalStateException(StatusMessages.replacementLocationSaveFailed()),
            )
        }
        return kotlin.Result.success(Unit)
    }

    private suspend fun recoverAfterReplacementFailure(
        previousState: com.kardinal.vpncontrol.model.PersistedState,
        switchAttempted: Boolean,
        orchestrator: BenchmarkOrchestrator,
        vpnManager: VpnManager,
    ): String {
        if (!switchAttempted) {
            storage.restoreSelection(
                previousState,
                restoreRuntimeArtifacts = true,
                sourceUrlOverride = "",
            )
            return StatusMessages.backgroundRefreshPreviousLocationKept(previousState.appMode)
        }
        val previousSelection = orchestrator.rehydrateSelection(previousState)
        if (previousSelection.isSuccess) {
            val restartResult = vpnManager.start(previousSelection.getOrThrow())
            if (restartResult.isSuccess) {
                storage.restoreSelection(
                    previousState,
                    restoreRuntimeArtifacts = false,
                    sourceUrlOverride = "",
                )
                return StatusMessages.backgroundRefreshPreviousLocationKept(previousState.appMode)
            }
        }
        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                storage.clearSelection()
                StatusMessages.backgroundRefreshReplacementStopped(previousState.appMode)
            },
            onFailure = { error ->
                StatusMessages.backgroundRefreshRestoreOrStopFailed(previousState.appMode, error.message.orEmpty())
            },
        )
    }

    private suspend fun stopVpnForBackgroundPermissionLoss(
        previousState: com.kardinal.vpncontrol.model.PersistedState,
        vpnManager: VpnManager,
    ): String {
        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                storage.clearSelection()
                StatusMessages.backgroundRefreshReplacementStopped(previousState.appMode)
            },
            onFailure = { error ->
                storage.restoreSelection(
                    previousState,
                    restoreRuntimeArtifacts = true,
                    sourceUrlOverride = "",
                )
                StatusMessages.backgroundRefreshRestoreOrStopFailed(previousState.appMode, error.message.orEmpty())
            },
        )
    }

    private fun didDispatchVpnSwitchAttempt(error: Throwable): Boolean {
        return (error as? VpnCommandException)?.commandDispatched ?: true
    }

    private fun connectionLabel(appMode: AppMode): String {
        return when (appMode) {
            AppMode.VPN -> "VPN"
            AppMode.PROXY_ONLY -> "proxy"
        }
    }

    private fun backgroundSelectionSourceLabel(
        sourceUrl: String,
        state: com.kardinal.vpncontrol.model.PersistedState,
    ): String? {
        val normalized = sourceUrl.trim()
        if (normalized.isBlank()) return null
        val subscription = state.subscriptions.firstOrNull { it.url == normalized } ?: return null
        return subscription.customName.ifBlank {
            RemoteSourceResolver.preview(subscription.url)?.title ?: "Remote source"
        }
    }
}
