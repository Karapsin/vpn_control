package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.parseDirectRemoteSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class DesktopAutoRefreshScheduler(
    private val scope: CoroutineScope,
    private val runAutoRefreshCycle: suspend () -> Unit,
) {
    constructor(
        service: DesktopAppService,
        scope: CoroutineScope,
    ) : this(
        scope = scope,
        runAutoRefreshCycle = service::runAutoRefreshCycle,
    )

    private data class Config(
        val enabled: Boolean,
        val intervalMillis: Long,
    )

    private var activeJob: Job? = null
    private var activeConfig: Config? = null

    fun sync(state: MainUiState) {
        val nextConfig = state.toSchedulerConfig()
        if (nextConfig == activeConfig && activeJob?.isActive == true) {
            return
        }
        activeJob?.cancel()
        activeConfig = nextConfig
        if (!nextConfig.enabled) {
            activeJob = null
            return
        }
        activeJob = scope.launch {
            while (isActive) {
                delay(nextConfig.intervalMillis)
                if (!isActive) break
                runAutoRefreshCycle()
            }
        }
    }

    fun cancel() {
        activeJob?.cancel()
        activeJob = null
        activeConfig = null
    }

    private fun MainUiState.toSchedulerConfig(): Config {
        val intervalMinutes = subscriptionRefreshPolicy
            .effectiveIntervalMinutes(subscriptionRefreshCustomHours)
        val hasSupportedSubscription = subscriptions.any { subscription ->
            subscription.url.isNotBlank() && parseDirectRemoteSource(subscription.url) is DirectRemoteSourceResolution
        }
        val enabled = profileSourceMode == com.kardinal.vpncontrol.model.ProfileSourceMode.SUBSCRIPTION &&
            intervalMinutes != null &&
            hasSupportedSubscription
        return Config(
            enabled = enabled,
            intervalMillis = ((intervalMinutes ?: 0L) * 60_000L).coerceAtLeast(0L),
        )
    }
}
