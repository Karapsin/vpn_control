package com.kardinal.vpncontrol.data

import android.content.Context
import android.net.VpnService
import androidx.work.WorkManager
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.AppMode
import java.io.IOException
import kotlinx.coroutines.delay

class SubscriptionRefreshWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    private val storage = ProfileStorage(appContext)

    override suspend fun doWork(): Result {
        val state = storage.snapshot()
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION ||
            state.subscriptionRefreshPolicy == SubscriptionRefreshPolicy.OFF ||
            state.profileUrl.isBlank()
        ) {
            WorkManager.getInstance(applicationContext)
                .cancelUniqueWork(SubscriptionRefreshScheduler.WORK_NAME)
            DiagnosticsLogger.append(
                applicationContext,
                "Background subscription sync skipped: mode=${state.profileSourceMode} policy=${state.subscriptionRefreshPolicy} urlSet=${state.profileUrl.isNotBlank()}",
            )
            return Result.success()
        }
        if (RemoteSourceResolver.validateProfileSource(state.profileUrl).isFailure) {
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
        return orchestrator.syncSubscriptionLocations().fold(
            onSuccess = { syncResult ->
                if (syncResult.selectedMissing && state.isVpnRunning) {
                    if (state.appMode == AppMode.VPN && VpnService.prepare(applicationContext) != null) {
                        val stopMessage = stopVpnForBackgroundPermissionLoss(
                            previousState = state,
                            vpnManager = vpnManager,
                        )
                        storage.updateStatus(
                            "Selected subscription location is no longer available. VPN permission is required to switch in background. $stopMessage".trim(),
                        )
                        DiagnosticsLogger.append(
                            applicationContext,
                            "Background subscription sync skipped auto-switch because VPN permission is not available in background",
                        )
                        return@fold Result.success()
                    }
                    storage.updateStatus("Selected subscription location is no longer available. Finding a new best location...")
                    var switchFailure: Throwable? = null
                    val replacement = findBestProfileWithRetries(
                        orchestrator = orchestrator,
                        retryCount = state.validationSettings.retryCount,
                    )
                    if (replacement.isSuccess) {
                        val selection = replacement.getOrThrow()
                        val switchResult = startReplacementLocation(
                            selection = selection,
                            sourceUrl = state.profileUrl,
                            vpnManager = vpnManager,
                        )
                        if (switchResult.isSuccess) {
                            storage.updateStatus(
                                "Subscription changed. Switched ${connectionLabel(state.appMode)} to ${selection.profile.remarks}",
                            )
                            DiagnosticsLogger.append(
                                applicationContext,
                                "Background subscription sync switched ${connectionLabel(state.appMode)} to replacement location: ${selection.profile.remarks}",
                            )
                            return@fold Result.success()
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
                        "Selected subscription location disappeared. $failureMessage $rollbackMessage".trim(),
                    )
                    DiagnosticsLogger.append(
                        applicationContext,
                        "Background subscription sync could not switch to replacement location: $failureMessage",
                    )
                    return@fold Result.success()
                }
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync complete: selectedMissing=${syncResult.selectedMissing}",
                )
                Result.success()
            },
            onFailure = { error ->
                if (state.activeSubscriptionId.isNotBlank()) {
                    storage.updateSubscriptionRefreshStatus(
                        subscriptionId = state.activeSubscriptionId,
                        status = error.message ?: "Background refresh failed",
                    )
                }
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync failed: ${error.message ?: error::class.java.simpleName}",
                )
                if (error is IOException && runAttemptCount < 3) {
                    Result.retry()
                } else {
                    Result.failure()
                }
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
    ): kotlin.Result<Unit> {
        val appMode = storage.snapshot().appMode
        storage.updateStatus("Starting ${connectionLabel(appMode)} with the new best location...")
        val startResult = vpnManager.start(selection)
        if (startResult.isFailure) {
            return kotlin.Result.failure(
                startResult.exceptionOrNull() ?: IllegalStateException("Failed to start ${connectionLabel(appMode)} with the new best location"),
            )
        }
        val persistResult = runCatching {
            storage.updateSelection(
                profile = selection.profile,
                summary = selection.benchmark.detail,
                runtimeConfigJson = selection.runtimeConfigJson,
                sourceUrl = sourceUrl,
            )
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
}
