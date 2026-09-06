package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import java.nio.file.Files
import java.nio.file.Path
import java.util.ArrayDeque

internal class DesktopRuntimeStatusService(
    private val stateProvider: () -> MainUiState,
    private val currentMode: () -> AppMode?,
    private val currentPort: () -> Int?,
    private val lastPreflightReport: () -> DesktopPreflightReport?,
    private val desktopVpnCapabilityStatus: () -> String,
    private val currentLogFile: () -> Path?,
    private val defaultLogFile: () -> Path,
) {
    fun presentation(): DesktopRuntimePresentation {
        val state = stateProvider()
        val report = lastPreflightReport().takeIf { state.appMode == AppMode.VPN }
        return DesktopRuntimePresentation(currentMode() ?: state.appMode, currentPort(), report?.appMode,
            report?.checks?.count { it.status == DesktopPreflightStatus.FAIL })
    }

    fun details(): List<String> {
        val state = stateProvider()
        val runtimeMode = currentMode() ?: state.appMode
        val details = mutableListOf<String>()
        details += RuntimeStatusMessages.runtimeMode(runtimeMode.name)
        currentPort()?.let { details += RuntimeStatusMessages.localProxy("127.0.0.1:$it") }
        if (state.appMode == AppMode.VPN) {
            val preflight = lastPreflightReport()
            if (preflight != null) {
                details += preflight.summary()
                preflight.checks
                    .filter { it.status == DesktopPreflightStatus.FAIL }
                    .take(2)
                    .forEach { details += it.line() }
            } else {
                details += desktopVpnCapabilityStatus()
            }
        }
        val logPath = currentLogFile() ?: defaultLogFile()
        runtimeOutboundIssueHint(state, logPath)?.let { details += it }
        details += RuntimeStatusMessages.runtimeLog(logPath.toString())
        return details
    }

    private fun runtimeOutboundIssueHint(state: MainUiState, logPath: Path): String? {
        if (!state.isVpnRunning) return null
        val recentLines = recentLogLines(logPath)
        val outboundFailures = recentLines.count { line ->
            val normalized = line.lowercase()
            "outbound/" in normalized &&
                ("timeout" in normalized || "timed out" in normalized || "reset by peer" in normalized)
        }
        return if (outboundFailures >= RECENT_OUTBOUND_FAILURE_THRESHOLD) {
            "Runtime outbound has repeated timeouts or resets; try another location or Find Best."
        } else {
            null
        }
    }

    private fun recentLogLines(logPath: Path): List<String> {
        if (!Files.isRegularFile(logPath)) return emptyList()
        return runCatching {
            val lines = ArrayDeque<String>(RECENT_LOG_LINE_LIMIT)
            Files.newBufferedReader(logPath).useLines { sequence ->
                sequence.forEach { line ->
                    if (lines.size == RECENT_LOG_LINE_LIMIT) {
                        lines.removeFirst()
                    }
                    lines.addLast(line)
                }
            }
            lines.toList()
        }.getOrDefault(emptyList())
    }

    private companion object {
        const val RECENT_LOG_LINE_LIMIT = 120
        const val RECENT_OUTBOUND_FAILURE_THRESHOLD = 3
    }
}
