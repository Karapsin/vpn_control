package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import java.nio.file.Path

internal class DesktopDiagnosticsService(
    private val stateProvider: () -> MainUiState,
    private val desktopStore: DesktopStateStore,
    private val runtimeManager: DesktopProxyRuntimeManager,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    suspend fun export(selection: Result<Path?>) {
        if (selection.isFailure) {
            updateState {
                it.withStatus(selection.exceptionOrNull()?.message ?: "Failed to open diagnostics destination")
            }
            return
        }
        val target = selection.getOrNull() ?: run {
            updateState { it.withStatus("Diagnostics export canceled") }
            return
        }
        val report = DesktopDiagnosticsExporter.buildReport(
            state = stateProvider(),
            runtimeMode = runtimeManager.currentMode(),
            currentPort = runtimeManager.currentPort(),
            runtimeProcessId = runtimeManager.currentProcessId(),
            logFile = runtimeManager.currentLogFile() ?: runtimeManager.defaultLogFile(),
            runtimeConfigJson = desktopStore.readRuntimeConfig() ?: runtimeManager.lastAttemptedConfigJson(),
            preflightReport = runtimeManager.lastPreflightReport(),
            vpnCapabilityStatus = runtimeManager.desktopVpnCapabilityStatus(),
        )
        val result = DesktopTextTransfer.writeTextFile(target, report)
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path -> "Diagnostics exported to $path" },
                    onFailure = { error -> error.message ?: "Failed to export diagnostics" },
                ),
            )
        }
    }
}
