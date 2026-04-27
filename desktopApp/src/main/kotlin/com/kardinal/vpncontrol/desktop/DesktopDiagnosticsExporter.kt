package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

object DesktopDiagnosticsExporter {
    private val timestampFormatter = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
        .withZone(ZoneId.systemDefault())

    fun suggestedFileName(): String {
        return "vpn-control-desktop-diagnostics-${timestampFormatter.format(Instant.now())}.txt"
    }

    fun buildReport(
        state: MainUiState,
        runtimeMode: AppMode?,
        currentPort: Int?,
        runtimeProcessId: Long?,
        logFile: Path?,
        runtimeConfigJson: String?,
        preflightReport: DesktopPreflightReport?,
        vpnCapabilityStatus: String?,
    ): String {
        val logTail = logFile
            ?.takeIf { Files.exists(it) }
            ?.let { path ->
                runCatching {
                    Files.readAllLines(path)
                        .takeLast(120)
                        .joinToString(separator = "\n")
                }.getOrNull()
            }
            .orEmpty()

        return buildString {
            appendLine("VPN Control Desktop Diagnostics")
            appendLine("generated_at=${Instant.now()}")
            appendLine("status=${state.statusMessage}")
            appendLine("app_mode=${state.appMode}")
            appendLine("runtime_mode=${runtimeMode ?: "none"}")
            appendLine("runtime_process_id=${runtimeProcessId ?: "none"}")
            appendLine("profile_source_mode=${state.profileSourceMode}")
            appendLine("is_runtime_running=${state.isVpnRunning}")
            appendLine("active_subscription_id=${state.activeSubscriptionId}")
            appendLine("selected_profile_name=${state.selectedProfileName}")
            appendLine("selected_profile_server=${state.selectedProfileServer}")
            appendLine("selected_profile_source_url=${state.selectedProfileSourceUrl}")
            appendLine("selected_profile_raw_present=${state.selectedProfileRawLink.isNotBlank()}")
            appendLine("current_proxy_port=${currentPort ?: "none"}")
            appendLine("runtime_log_file=${logFile?.toAbsolutePath() ?: "none"}")
            appendLine("last_benchmark_summary=${state.lastBenchmarkSummary}")
            appendLine("find_best_state=${findBestState(state)}")
            appendLine("successful_starts=${state.successfulStarts}")
            appendLine("successful_stops=${state.successfulStops}")
            appendLine("os_name=${System.getProperty("os.name")}")
            appendLine("os_arch=${System.getProperty("os.arch")}")
            appendLine("java_version=${System.getProperty("java.version")}")
            appendLine("user_name=${System.getProperty("user.name")}")
            appendLine()
            appendLine("[subscription_refresh]")
            if (state.subscriptions.isEmpty()) {
                appendLine("<empty>")
            } else {
                state.subscriptions.forEach { subscription ->
                    appendLine(
                        listOf(
                            "id=${subscription.id}",
                            "name=${subscription.customName.ifBlank { subscription.url.substringAfter("://").substringBefore('/') }}",
                            "cached=${subscription.cachedLocations.size}",
                            "last_refreshed_at=${subscription.lastRefreshedAtEpochMillis}",
                            "status=${subscription.lastRefreshStatus.ifBlank { "not refreshed yet" }}",
                        ).joinToString(" | "),
                    )
                }
            }
            appendLine()
            appendLine("[vpn_capability]")
            appendLine(vpnCapabilityStatus ?: "<unknown>")
            appendLine()
            appendLine("[preflight]")
            if (preflightReport == null) {
                appendLine("<none>")
            } else {
                preflightReport.lines().forEach(::appendLine)
            }
            appendLine()
            appendLine("[runtime_config]")
            appendLine(runtimeConfigJson?.ifBlank { "<empty>" } ?: "<none>")
            appendLine()
            appendLine("[connection_log]")
            state.connectionLog.forEach { entry ->
                appendLine("${entry.createdAtEpochMillis}: ${entry.message}")
            }
            appendLine()
            appendLine("[runtime_log_tail]")
            appendLine(logTail.ifBlank { "<empty>" })
        }
    }

    private fun findBestState(state: MainUiState): String {
        return when {
            state.isRefreshing && state.isBusy -> "running"
            state.isRefreshing -> "refreshing"
            state.lastBenchmarkSummary.isNotBlank() -> "last_result=${state.lastBenchmarkSummary}"
            else -> "not_run"
        }
    }
}
