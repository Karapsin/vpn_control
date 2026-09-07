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
import java.util.UUID

class SubscriptionRefreshWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    private val owner = com.kardinal.vpncontrol.AndroidApplicationOwner.get(appContext)
    private val storage = owner.storage

    private var recoveryPoint: com.kardinal.vpncontrol.AndroidRuntimeRestorePoint? = null
    private var recoveryWarning: String? = null
    private var retainedSession: com.kardinal.vpncontrol.AndroidRetainedRuntimeSession? = null

    override suspend fun doWork(): Result {
        val state = storage.snapshot()
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION || state.subscriptionRefreshPolicy == SubscriptionRefreshPolicy.OFF)
            return Result.success()
        val result = owner.refreshSubscriptions("active", ::afterRefresh)
        if (result.code == com.kardinal.vpncontrol.model.ControlCode.BUSY ||
            result.code == com.kardinal.vpncontrol.model.ControlCode.CONFLICT) return Result.retry()
        return Result.success()
    }

    private suspend fun afterRefresh(previousState: com.kardinal.vpncontrol.model.PersistedState,
        batch: SubscriptionRefreshBatchResult, point: com.kardinal.vpncontrol.AndroidRuntimeRestorePoint?): List<String> {
        recoveryPoint = point
        recoveryWarning = null
        if (point != null && owner.runtimeObserver.state.value != point.observation) return listOf("REFRESH_RUNTIME_CHANGED")
        val state = previousState.copy(isVpnRunning = point != null, appMode = point?.configuration?.mode ?: previousState.appMode)
        val refreshAll = isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
        val orchestrator = owner.orchestrator
        val vpnManager = owner.vpnManager
        val repository = owner.repository
        suspend fun finishAndScheduleNext(outcome: String = "success"): List<String> {
            return (if (outcome in setOf("replacement_failed", "vpn_permission_unavailable", "refresh_failed"))
                listOf("REFRESH_" + outcome.uppercase(java.util.Locale.ROOT)) else emptyList()) + listOfNotNull(recoveryWarning)
        }
        if (batch.refreshedCount == 0) return finishAndScheduleNext("refresh_failed")
        val previousSelectedStored = LocationConfigs.selectedStoredReference(state.selectedProfileJson, state.selectedProfileRawLink)
        val refreshResult = kotlin.Result.success(batch)
        var releaseFailed = false
        val outcome = try { refreshResult.fold(
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
                        storage.updateStatus(ConnectionStatusMessages.backgroundVpnPermissionRequiredKeepingPrevious())
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background subscription sync skipped auto-switch because VPN permission is not available in background",
                        )
                        return@fold finishAndScheduleNext("vpn_permission_unavailable")
                    }
                    retainedSession = owner.retainedRuntimeServices.acquire(requireNotNull(point).observation)
                    if (retainedSession == null) return@fold listOf("REFRESH_RUNTIME_SERVICE_UNAVAILABLE")
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
                            return@fold finishAndScheduleNext("switched_to_best")
                        }
                        switchFailure = switchResult.exceptionOrNull()
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background replacement switch failed: ${diagnosticsErrorSummary(switchFailure)}",
                        )
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
                    return@fold finishAndScheduleNext("replacement_failed")
                }

                if (selectedMissing && state.isVpnRunning) {
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
                    return@fold finishAndScheduleNext("selected_missing_kept_previous")
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
                finishAndScheduleNext("refreshed_without_switch")
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
                finishAndScheduleNext("refresh_failed")
            },
        ) } finally {
            releaseFailed = retainedSession?.let { runCatching { it.release().getOrThrow() }.isFailure } == true
            retainedSession = null
        }
        return outcome + if (releaseFailed) listOf("REFRESH_SERVICE_RELEASE_FAILED") else emptyList()
    }

    private suspend fun findBestProfileWithRetries(
        orchestrator: BenchmarkOrchestrator,
        retryCount: Int,
    ): kotlin.Result<ProfileSelectionAttemptPlan> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = retryCount,
            onRetryStatus = storage::updateStatus,
            action = orchestrator::refreshCachedBestProfileAttemptPlan,
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
        var currentIndex = 0
        while (currentIndex < attemptPlan.attempts.size) {
            val window = BenchmarkSearchLogic.activeVerificationWindow(
                attempts = attemptPlan.attempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            )
            storage.updateStatus(
                BenchmarkStatusMessages.testingLocationsRange(
                    start = currentIndex + 1,
                    end = currentIndex + window.size,
                    total = attemptPlan.attempts.size,
                ),
            )
            val precheck = BenchmarkSearchLogic.validateCandidateWindowForBestPass(
                attempts = attemptPlan.attempts,
                currentIndex = currentIndex,
                windowSize = verificationWindowSize,
            ) { candidate, attemptIndex ->
                val rawKey = LocationConfigs.encodeStoredLocation(candidate.selection.profile)
                candidateBenchmarks[rawKey] ?: orchestrator.verifySelectionCandidate(candidate, attemptIndex)
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
                recordLocationBenchmark(result.benchmark)
            }
            val verifiedCandidates = precheck.verifiedCandidates
            if (verifiedCandidates.isEmpty()) {
                val skipSummary = BenchmarkSearchLogic.strictTargetSkipSummary(
                    precheck.completed.map { it.benchmark },
                )
                if (skipSummary.isNotBlank()) {
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background best-location strict target skipped window: $skipSummary",
                    )
                    lastFailure = IllegalStateException(skipSummary)
                } else {
                    lastFailure = precheck.completed.lastOrNull()?.benchmark?.detail?.let(::IllegalStateException)
                        ?: lastFailure
                }
                currentIndex += window.size.coerceAtLeast(1)
                continue
            }

            for (winner in verifiedCandidates) {
                val attempt = winner.attempt
                storage.updateStatus(
                    BenchmarkStatusMessages.tryingBestCandidate(
                        attempt = winner.attemptIndex + 1,
                        total = attemptPlan.attempts.size,
                        remarks = attempt.selection.profile.remarks,
                    ),
                )
                val appMode = storage.snapshot().appMode
                storage.updateStatus(ConnectionStatusMessages.startingConnectionWithBestLocation(appMode))
                onSwitchAttempted()
                val expected = owner.runtimeObserver.state.value
                if (expected.knowledge == com.kardinal.vpncontrol.AndroidRuntimeKnowledge.UNKNOWN)
                    return kotlin.Result.failure(IllegalStateException("RUNTIME_OUTCOME_UNKNOWN"))
                val startResult = vpnManager.startRetained(attempt.selection, requireNotNull(retainedSession), expected)
                if (startResult.isFailure) {
                    if (owner.runtimeObserver.state.value.knowledge == com.kardinal.vpncontrol.AndroidRuntimeKnowledge.UNKNOWN ||
                        (startResult.exceptionOrNull() as? VpnCommandException)?.outcomeUnknown == true) return startResult.map { attempt.selection }
                    lastFailure = startResult.exceptionOrNull()
                    recordLocationBenchmark(
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = attempt.preflight,
                            reason = startResult.exceptionOrNull()?.message ?: "start_failed",
                            secondaryStatus = "error",
                        ),
                    )
                    continue
                }

                storage.updateStatus(BenchmarkStatusMessages.verifyingBlockedResource(attempt.selection.profile.remarks))
                val attemptRawKey = LocationConfigs.encodeStoredLocation(attempt.selection.profile)
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background active verification begin: profile=${attempt.selection.profile.remarks} " +
                        "attempt=${winner.attemptIndex + 1}/${attemptPlan.attempts.size}",
                )
                val verificationBenchmark = orchestrator.verifyActiveSelection(attempt)
                    .getOrElse { error ->
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background active verification call failed: profile=${attempt.selection.profile.remarks} " +
                                "attempt=${winner.attemptIndex + 1}/${attemptPlan.attempts.size} " +
                                "error=${diagnosticsErrorSummary(error)}",
                        )
                        BenchmarkSearchLogic.failedActiveVerificationBenchmark(
                            candidate = attempt.preflight,
                            reason = error.message ?: "active_verification_failed",
                            secondaryStatus = "error",
                        )
                    }
                candidateBenchmarks[attemptRawKey] = verificationBenchmark
                recordLocationBenchmark(verificationBenchmark)
                if (verificationBenchmark.testStatus == "ok") {
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background active verification accepted: profile=${attempt.selection.profile.remarks} " +
                            "attempt=${winner.attemptIndex + 1}/${attemptPlan.attempts.size} detail=${verificationBenchmark.detail}",
                    )
                    val verifiedSelection = attempt.selection.copy(benchmark = verificationBenchmark)
                    val persistResult = runCatching {
                        repository.persistSelection(
                            verifiedSelection,
                            verifiedSelection.sourceUrl.ifBlank { sourceUrl },
                        )
                    }
                    if (persistResult.isFailure) {
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background verified selection persist failed: profile=${attempt.selection.profile.remarks} " +
                                "error=${diagnosticsErrorSummary(persistResult.exceptionOrNull())}",
                        )
                        return kotlin.Result.failure(
                            persistResult.exceptionOrNull()
                                ?: IllegalStateException(SubscriptionStatusMessages.replacementLocationSaveFailed()),
                        )
                    }
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background verified selection persisted: profile=${attempt.selection.profile.remarks}",
                    )
                    return kotlin.Result.success(verifiedSelection)
                }

                lastFailure = IllegalStateException(verificationBenchmark.detail)
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background active verification rejected: profile=${attempt.selection.profile.remarks} " +
                        "attempt=${winner.attemptIndex + 1}/${attemptPlan.attempts.size} " +
                        "status=${verificationBenchmark.testStatus} detail=${verificationBenchmark.detail}",
                )
                storage.updateStatus(
                    BenchmarkStatusMessages.switchingAfterVerificationFailure(attempt.selection.profile.remarks),
                )
                val stopResult = vpnManager.stopRetained(owner.runtimeObserver.state.value, requireNotNull(retainedSession))
                if (stopResult.isFailure) return stopResult.map { attempt.selection }
                stopResult.exceptionOrNull()?.let { error ->
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background stop after verification failure failed: profile=${attempt.selection.profile.remarks} " +
                            "error=${diagnosticsErrorSummary(error)}",
                    )
                }
            }
            currentIndex += window.size.coerceAtLeast(1)
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
        storage.updateStatus(benchmark.detail)
    }

    private suspend fun recoverAfterReplacementFailure(
        previousState: com.kardinal.vpncontrol.model.PersistedState,
        switchAttempted: Boolean,
        orchestrator: BenchmarkOrchestrator,
        vpnManager: VpnManager,
    ): String {
        val point = recoveryPoint ?: return "RUNTIME_OUTCOME_UNKNOWN".also { recoveryWarning = it }
        val outcome = com.kardinal.vpncontrol.recoverAndroidRefresh(point, switchAttempted,
            { owner.runtimeObserver.state.value }, { expected -> vpnManager.stopRetained(expected, requireNotNull(retainedSession)) },
            { actual, stopped -> vpnManager.restoreRetained(actual, stopped, requireNotNull(retainedSession)) }, owner.runtimeObserver::captureRuntime)
        recoveryWarning = outcome
        if (outcome == "RUNTIME_NOT_CHANGED" && vpnManager.restoreUnchangedRuntimeArtifacts(point).isFailure)
            recoveryWarning = "RUNTIME_ARTIFACT_RESTORE_FAILED"
        return if (outcome in setOf("RUNTIME_NOT_CHANGED", "RUNTIME_RESTORED"))
            SubscriptionStatusMessages.backgroundRefreshPreviousLocationKept(point.configuration.mode) else outcome
    }

    private fun didDispatchVpnSwitchAttempt(error: Throwable): Boolean {
        return (error as? VpnCommandException)?.commandDispatched ?: true
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
