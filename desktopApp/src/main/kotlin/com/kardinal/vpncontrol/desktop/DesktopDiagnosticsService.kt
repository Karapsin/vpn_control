package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DiagnosticsStatusMessages
import com.kardinal.vpncontrol.MainUiState
import java.nio.file.Path

internal class DesktopDiagnosticsService(
    private val stateProvider: () -> MainUiState,
    private val desktopStore: DesktopStateStore,
    private val runtimeManager: DesktopProxyRuntimeManager,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    suspend fun report(): String = DesktopDiagnosticsExporter.buildReport(
        state = stateProvider(),
        runtimeMode = runtimeManager.currentMode(),
        currentPort = runtimeManager.currentPort(),
        runtimeProcessId = runtimeManager.currentProcessId(),
        logFile = runtimeManager.currentLogFile() ?: runtimeManager.defaultLogFile(),
        runtimeConfigJson = desktopStore.readRuntimeConfig() ?: runtimeManager.lastAttemptedConfigJson(),
        preflightReport = runtimeManager.lastPreflightReport(),
        vpnCapabilityStatus = runtimeManager.desktopVpnCapabilityStatus(),
    )

    suspend fun export(selection: Result<Path?>) {
        if (selection.isFailure) {
            updateState {
                it.withStatus(
                    DesktopDiagnosticsExportLogic.destinationSelectionFailureMessage(selection.exceptionOrNull()),
                )
            }
            return
        }
        val target = selection.getOrNull() ?: run {
            updateState { it.withStatus(DiagnosticsStatusMessages.diagnosticsExportCanceled()) }
            return
        }
        val report = report()
        val result = DesktopTextTransfer.writeTextFile(target, report)
        updateState {
            it.withStatus(DesktopDiagnosticsExportLogic.exportResultMessage(result))
        }
    }
}
