package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.parseDirectRemoteSource
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class DesktopAutoRefreshScheduler(
    private val scope: CoroutineScope,
    private val runAutoRefreshCycle: suspend () -> Unit,
    private val nowMillis: () -> Long = System::currentTimeMillis,
    private val logger: (String) -> Unit = {},
) {
    constructor(
        service: DesktopAppService,
        scope: CoroutineScope,
    ) : this(
        scope = scope,
        runAutoRefreshCycle = service::runAutoRefreshCycle,
        logger = { message -> println("[vpn-control] $message") },
    )

    private data class Config(
        val enabled: Boolean,
        val intervalMillis: Long,
        val initialDelayMillis: Long,
        val targetSignature: List<TargetSignature>,
    ) {
        fun sameScheduleAs(other: Config?): Boolean {
            return other != null &&
                enabled == other.enabled &&
                intervalMillis == other.intervalMillis &&
                targetSignature == other.targetSignature
        }
    }

    private data class TargetSignature(
        val id: String,
        val url: String,
    )

    private var activeJob: Job? = null
    private var activeConfig: Config? = null

    fun sync(state: MainUiState) {
        val nextConfig = state.toSchedulerConfig()
        if (nextConfig.sameScheduleAs(activeConfig) && activeJob?.isActive == true) {
            return
        }
        activeJob?.cancel()
        activeConfig = nextConfig
        if (!nextConfig.enabled) {
            activeJob = null
            return
        }
        logger(
            "auto-refresh scheduled: next run in ${formatDelay(nextConfig.initialDelayMillis)}, " +
                "interval ${formatDelay(nextConfig.intervalMillis)}",
        )
        activeJob = scope.launch {
            delay(nextConfig.initialDelayMillis)
            while (isActive) {
                if (!isActive) break
                logger("auto-refresh started")
                runCatching {
                    runAutoRefreshCycle()
                }.onFailure { error ->
                    logger("auto-refresh failed: ${error.message ?: error::class.simpleName ?: "unknown error"}")
                }
                if (!isActive) break
                delay(nextConfig.intervalMillis)
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
        val refreshTargets = if (profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            MainCommandLogic.currentSubscriptionSearchTargets(this)
        } else {
            emptyList()
        }
        val supportedTargets = refreshTargets.filter { it.isSupportedRemoteSource() }
        val enabled = profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
            intervalMinutes != null &&
            supportedTargets.isNotEmpty()
        val intervalMillis = ((intervalMinutes ?: 0L) * 60_000L).coerceAtLeast(0L)
        val targetSignature = supportedTargets.map { subscription ->
            TargetSignature(
                id = subscription.id,
                url = subscription.url,
            )
        }
        return Config(
            enabled = enabled,
            intervalMillis = intervalMillis,
            initialDelayMillis = if (enabled) {
                initialDelayMillis(intervalMillis, supportedTargets)
            } else {
                0L
            },
            targetSignature = targetSignature,
        )
    }

    private fun SubscriptionSource.isSupportedRemoteSource(): Boolean {
        return url.isNotBlank() && parseDirectRemoteSource(url) is DirectRemoteSourceResolution
    }

    private fun initialDelayMillis(
        intervalMillis: Long,
        targets: List<SubscriptionSource>,
    ): Long {
        if (intervalMillis <= 0L) return 0L
        val oldestRefresh = targets
            .map { it.lastRefreshedAtEpochMillis }
            .filter { it > 0L }
            .minOrNull()
            ?: return 0L
        val elapsedMillis = (nowMillis() - oldestRefresh).coerceAtLeast(0L)
        return (intervalMillis - elapsedMillis).coerceAtLeast(0L)
    }

    private fun formatDelay(delayMillis: Long): String {
        val totalSeconds = (delayMillis / 1_000L).coerceAtLeast(0L)
        val minutes = totalSeconds / 60L
        val seconds = totalSeconds % 60L
        return when {
            minutes > 0L && seconds > 0L -> "${minutes}m ${seconds}s"
            minutes > 0L -> "${minutes}m"
            else -> "${seconds}s"
        }
    }
}
