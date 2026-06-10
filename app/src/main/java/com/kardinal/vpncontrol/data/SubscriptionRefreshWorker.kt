package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import android.content.Context
import android.net.VpnService
import androidx.work.WorkManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.kardinal.vpncontrol.ConnectionOrchestrationLogic
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope

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
                        storage.updateStatus(ConnectionStatusMessages.backgroundVpnPermissionRequiredKeepingPrevious())
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background subscription sync skipped auto-switch because VPN permission is not available in background",
                        )
                        return@fold finishAndScheduleNext()
                    }
                    storage.updateStatus(SubscriptionStatusMessages.backgroundRefreshFindingBest())
                    var switchFailure: Throwable? = null
                    val replacement = findBestProfileWithRetries(
                        orchestrator = orchestrator,
                        retryCount = state.validationSettings.retryCount,
                    )
                    var switchAttempted = false
                    if (replacement.isSuccess) {
                        val switchResult = startReplacementLocation(
                            attemptPlan = replacement.getOrThrow(),
                            sourceUrl = state.profileUrl,
                            orchestrator = orchestrator,
                            vpnManager = vpnManager,
                            repository = repository,
                            onSwitchAttempted = { switchAttempted = true },
                        )
                        if (switchResult.isSuccess) {
                            val selection = switchResult.getOrThrow()
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
                        switchAttempted = switchAttempted || switchFailure?.let(::didDispatchVpnSwitchAttempt) == true,
                        orchestrator = orchestrator,
                        vpnManager = vpnManager,
                    )
                    val failureMessage = switchFailure?.message
                        ?: replacement.exceptionOrNull()?.message
                        ?: SubscriptionStatusMessages.replacementLocationSearchFailed()
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
                        status = error.message ?: SubscriptionStatusMessages.backgroundRefreshFailed(),
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
    ): kotlin.Result<ProfileSelectionAttemptPlan> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = retryCount,
            onRetryStatus = storage::updateStatus,
            action = orchestrator::refreshBestProfileAttemptPlan,
        )
    }

    private suspend fun startReplacementLocation(
        attemptPlan: ProfileSelectionAttemptPlan,
        sourceUrl: String,
        orchestrator: BenchmarkOrchestrator,
        vpnManager: VpnManager,
        repository: AppRepository,
        onSwitchAttempted: () -> Unit,
    ): kotlin.Result<ProfileSelection> {
        if (attemptPlan.attempts.isEmpty()) {
            return kotlin.Result.failure(
                IllegalStateException(attemptPlan.failureMessage ?: SubscriptionStatusMessages.replacementLocationSearchFailed()),
            )
        }
        var lastFailure: Throwable? = null
        val candidateBenchmarks = mutableMapOf<String, com.kardinal.vpncontrol.model.ProfileBenchmark>()
        val verificationWindowSize = storage.snapshot().validationSettings.normalized().activeVerificationWindowSize
        for ((index, attempt) in attemptPlan.attempts.withIndex()) {
            storage.updateStatus(
                BenchmarkStatusMessages.tryingBestCandidate(
                    attempt = index + 1,
                    total = attemptPlan.attempts.size,
                    remarks = attempt.selection.profile.remarks,
                ),
            )
            val appMode = storage.snapshot().appMode
            storage.updateStatus(ConnectionStatusMessages.startingConnectionWithBestLocation(appMode))
            onSwitchAttempted()
            val startResult = vpnManager.start(attempt.selection)
            if (startResult.isFailure) {
                lastFailure = startResult.exceptionOrNull()
                continue
            }

            storage.updateStatus(BenchmarkStatusMessages.verifyingBlockedResource(attempt.selection.profile.remarks))
            val attemptRawKey = LocationConfigs.encodeStoredLocation(attempt.selection.profile)
            val verificationBenchmark = coroutineScope {
                val window = BenchmarkSearchLogic.activeVerificationWindow(
                    attempts = attemptPlan.attempts,
                    currentIndex = index,
                    windowSize = verificationWindowSize,
                )
                val fallbackJobs = window.drop(1).mapIndexed { offset, fallback ->
                    val fallbackRawKey = LocationConfigs.encodeStoredLocation(fallback.selection.profile)
                    val cached = candidateBenchmarks[fallbackRawKey]
                    async {
                        CandidateBenchmarkResult(
                            rawKey = fallbackRawKey,
                            benchmark = cached ?: orchestrator.verifySelectionCandidate(
                                fallback,
                                index + offset + 1,
                            ).getOrElse { error ->
                                BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                                    candidate = fallback.preflight,
                                    reason = error.message ?: "background_verification_failed",
                                    secondaryStatus = "error",
                                )
                            },
                        )
                    }
                }
                val currentBenchmark = candidateBenchmarks[attemptRawKey] ?: orchestrator.verifyActiveSelection(attempt)
                    .getOrElse { error ->
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = attempt.preflight,
                            reason = error.message ?: "active_verification_failed",
                            secondaryStatus = "error",
                        )
                    }
                candidateBenchmarks[attemptRawKey] = currentBenchmark
                recordLocationBenchmark(currentBenchmark)
                if (currentBenchmark.secondaryStatus == "ok") {
                    fallbackJobs.filter { it.isCompleted && !it.isCancelled }.forEach { job ->
                        val result = job.await()
                        candidateBenchmarks[result.rawKey] = result.benchmark
                        recordLocationBenchmark(result.benchmark)
                    }
                    fallbackJobs.forEach { it.cancel() }
                    return@coroutineScope currentBenchmark
                }
                val fallbackResults = fallbackJobs.awaitAll()
                fallbackResults.forEach { result ->
                    candidateBenchmarks[result.rawKey] = result.benchmark
                    recordLocationBenchmark(result.benchmark)
                }
                currentBenchmark
            }
            if (verificationBenchmark.secondaryStatus == "ok") {
                val verifiedSelection = attempt.selection.copy(benchmark = verificationBenchmark)
                val persistResult = runCatching {
                    repository.persistSelection(
                        verifiedSelection,
                        verifiedSelection.sourceUrl.ifBlank { sourceUrl },
                    )
                }
                if (persistResult.isFailure) {
                    return kotlin.Result.failure(
                        persistResult.exceptionOrNull()
                            ?: IllegalStateException(SubscriptionStatusMessages.replacementLocationSaveFailed()),
                    )
                }
                return kotlin.Result.success(verifiedSelection)
            }

            lastFailure = IllegalStateException(verificationBenchmark.detail)
            storage.updateStatus(BenchmarkStatusMessages.switchingAfterVerificationFailure(attempt.selection.profile.remarks))
            vpnManager.stop()
        }
        return kotlin.Result.failure(
            lastFailure ?: IllegalStateException(
                attemptPlan.failureMessage ?: SubscriptionStatusMessages.replacementLocationSearchFailed(),
            ),
        )
    }

    private suspend fun recordLocationBenchmark(benchmark: com.kardinal.vpncontrol.model.ProfileBenchmark) {
        val state = storage.snapshot()
        val updatedDetails = state.locationBenchmarkDetails.toMutableMap()
        updatedDetails[LocationConfigs.encodeStoredLocation(benchmark.profile)] = benchmark.detail
        storage.updateLocationBenchmarkDetails(updatedDetails)
    }

    private data class CandidateBenchmarkResult(
        val rawKey: String,
        val benchmark: com.kardinal.vpncontrol.model.ProfileBenchmark,
    )

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
            return SubscriptionStatusMessages.backgroundRefreshPreviousLocationKept(previousState.appMode)
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
                return SubscriptionStatusMessages.backgroundRefreshPreviousLocationKept(previousState.appMode)
            }
        }
        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                storage.clearSelection()
                SubscriptionStatusMessages.backgroundRefreshReplacementStopped(previousState.appMode)
            },
            onFailure = { error ->
                SubscriptionStatusMessages.backgroundRefreshRestoreOrStopFailed(previousState.appMode, error.message.orEmpty())
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
                SubscriptionStatusMessages.backgroundRefreshReplacementStopped(previousState.appMode)
            },
            onFailure = { error ->
                storage.restoreSelection(
                    previousState,
                    restoreRuntimeArtifacts = true,
                    sourceUrlOverride = "",
                )
                SubscriptionStatusMessages.backgroundRefreshRestoreOrStopFailed(previousState.appMode, error.message.orEmpty())
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
