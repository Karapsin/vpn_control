package com.kardinal.vpncontrol.data

import android.content.Context
import android.net.VpnService
import androidx.work.WorkManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import kotlinx.coroutines.delay

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
                val failedSourceUrls = failedSubscriptions.map { it.sourceUrl }.toSet()
                val partialFailureMessage = backgroundRefreshFailureSummary(failedSubscriptions)
                val selectedSourceFailed = state.selectedProfileSourceUrl.isNotBlank() &&
                    state.selectedProfileSourceUrl in failedSourceUrls
                val selectedMissing =
                    if (refreshAll) {
                        previousSelectedStored.isNotBlank() &&
                            previousSelectedStored !in refreshedState.currentLocations
                    } else {
                        val activeLocations = refreshedState.subscriptions
                            .firstOrNull { it.id == refreshedState.activeSubscriptionId }
                            ?.cachedLocations
                            .orEmpty()
                        previousSelectedStored.isNotBlank() &&
                            state.selectedProfileSourceUrl.isNotBlank() &&
                            state.selectedProfileSourceUrl == state.profileUrl &&
                            previousSelectedStored !in activeLocations
                    }

                if (state.isVpnRunning && state.findBestAfterSubscriptionRefresh) {
                    if (state.appMode == AppMode.VPN && VpnService.prepare(applicationContext) != null) {
                        storage.restoreSelection(
                            state,
                            restoreRuntimeArtifacts = true,
                            sourceUrlOverride = "",
                        )
                        storage.updateStatus(
                            "Subscription refresh finished, but VPN permission is required to switch in background. Previous VPN location kept as a fallback.",
                        )
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background subscription sync skipped auto-switch because VPN permission is not available in background",
                        )
                        return@fold finishAndScheduleNext()
                    }
                    storage.updateStatus("Subscription refresh finished. Finding the best location...")
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
                                buildString {
                                    append("Subscriptions refreshed")
                                    if (failedSubscriptions.isNotEmpty()) {
                                        append(" with partial failures")
                                    }
                                    append(". Switched ${connectionLabel(state.appMode)} to ${selection.profile.remarks}")
                                    winnerSource?.let {
                                        append(" (best from $it)")
                                    }
                                    partialFailureMessage?.let {
                                        append(". ")
                                        append(it)
                                    }
                                },
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
                        ?: "Failed to find a replacement location"
                    storage.updateStatus(
                        buildString {
                            append("Subscription refresh finished. ")
                            append(failureMessage)
                            partialFailureMessage?.let {
                                append(". ")
                                append(it)
                            }
                            if (selectedSourceFailed) {
                                append(". Current ${connectionLabel(state.appMode)} location belongs to a subscription that did not refresh")
                            }
                            if (rollbackMessage.isNotBlank()) {
                                append(" ")
                                append(rollbackMessage)
                            }
                        }.trim(),
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
                        buildString {
                            append("Active subscription changed, but the current ${connectionLabel(state.appMode)} location was kept as a fallback")
                            partialFailureMessage?.let {
                                append(". ")
                                append(it)
                            }
                        },
                    )
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background subscription sync kept previous ${connectionLabel(state.appMode)} location as fallback after active subscription changed",
                    )
                    return@fold finishAndScheduleNext()
                }

                if (state.isVpnRunning) {
                    storage.updateStatus(
                        buildString {
                            append("Subscriptions refreshed")
                            if (failedSubscriptions.isNotEmpty()) {
                                append(" with partial failures")
                            }
                            append(". Current ${connectionLabel(state.appMode)} location kept")
                            if (selectedSourceFailed) {
                                append(" from the previous cache")
                            }
                            partialFailureMessage?.let {
                                append(". ")
                                append(it)
                            }
                        },
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
                        status = error.message ?: "Background refresh failed",
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
        val normalizedRetries = retryCount.coerceAtLeast(0)
        var lastFailure: Throwable? = null
        repeat(normalizedRetries + 1) { attempt ->
            if (attempt > 0) {
                storage.updateStatus(
                    "Retrying best location search (${attempt + 1}/${normalizedRetries + 1})...",
                )
                delay(750)
            }
            val result = orchestrator.refreshBestProfile()
            if (result.isSuccess) {
                return result
            }
            lastFailure = result.exceptionOrNull()
        }
        return kotlin.Result.failure(
            lastFailure ?: IllegalStateException("Location search failed"),
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
                startResult.exceptionOrNull() ?: IllegalStateException("Failed to start ${connectionLabel(appMode)} with the new best location"),
            )
        }
        val persistResult = runCatching {
            repository.persistSelection(selection, sourceUrl)
        }
        if (persistResult.isFailure) {
            return kotlin.Result.failure(
                persistResult.exceptionOrNull() ?: IllegalStateException("Failed to save the replacement location"),
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
            return "Previous ${connectionLabel(previousState.appMode)} location kept as a fallback outside the current subscription."
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
                return "Previous ${connectionLabel(previousState.appMode)} location kept as a fallback outside the current subscription."
            }
        }
        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                storage.clearSelection()
                "${connectionLabel(previousState.appMode).replaceFirstChar { it.uppercase() }} was stopped because a replacement location could not be activated."
            },
            onFailure = { error ->
                "Failed to restore or stop ${connectionLabel(previousState.appMode)} cleanly: ${error.message ?: "live state may not match the saved state"}."
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
                "${connectionLabel(previousState.appMode).replaceFirstChar { it.uppercase() }} was stopped."
            },
            onFailure = { error ->
                storage.restoreSelection(
                    previousState,
                    restoreRuntimeArtifacts = true,
                    sourceUrlOverride = "",
                )
                "Failed to stop ${connectionLabel(previousState.appMode)} cleanly: ${error.message ?: "the previous location was kept as a fallback outside the current subscription"}."
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

    private fun backgroundRefreshFailureSummary(
        failures: List<SubscriptionRefreshFailure>,
    ): String? {
        if (failures.isEmpty()) return null
        val labels = failures
            .map { it.displayName }
            .distinct()
        val visible = labels.take(2).joinToString(", ")
        val overflow = (labels.size - 2).coerceAtLeast(0)
        return if (overflow > 0) {
            "Failed to refresh: $visible +$overflow more"
        } else {
            "Failed to refresh: $visible"
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
