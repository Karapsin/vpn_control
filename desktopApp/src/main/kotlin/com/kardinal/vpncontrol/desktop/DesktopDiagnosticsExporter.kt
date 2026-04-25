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
        logFile: Path?,
        runtimeConfigJson: String?,
        preflightReport: DesktopPreflightReport?,
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
            appendLine("profile_source_mode=${state.profileSourceMode}")
            appendLine("is_runtime_running=${state.isVpnRunning}")
            appendLine("active_subscription_id=${state.activeSubscriptionId}")
            appendLine("selected_profile_name=${state.selectedProfileName}")
            appendLine("selected_profile_server=${state.selectedProfileServer}")
            appendLine("selected_profile_source_url=${state.selectedProfileSourceUrl}")
            appendLine("current_proxy_port=${currentPort ?: "none"}")
            appendLine("runtime_log_file=${logFile?.toAbsolutePath() ?: "none"}")
            appendLine("last_benchmark_summary=${state.lastBenchmarkSummary}")
            appendLine("successful_starts=${state.successfulStarts}")
            appendLine("successful_stops=${state.successfulStops}")
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
}
