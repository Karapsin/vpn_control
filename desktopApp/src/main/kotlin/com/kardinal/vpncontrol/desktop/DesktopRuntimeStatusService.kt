package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages
import java.nio.file.Path

internal class DesktopRuntimeStatusService(
    private val stateProvider: () -> MainUiState,
    private val currentMode: () -> AppMode?,
    private val currentPort: () -> Int?,
    private val lastPreflightReport: () -> DesktopPreflightReport?,
    private val desktopVpnCapabilityStatus: () -> String,
    private val currentLogFile: () -> Path?,
    private val defaultLogFile: () -> Path,
) {
    fun details(): List<String> {
        val state = stateProvider()
        val runtimeMode = currentMode() ?: state.appMode
        val details = mutableListOf<String>()
        details += StatusMessages.runtimeMode(runtimeMode.name)
        currentPort()?.let { details += StatusMessages.localProxy("127.0.0.1:$it") }
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
        details += StatusMessages.runtimeLog(logPath.toString())
        return details
    }
}
