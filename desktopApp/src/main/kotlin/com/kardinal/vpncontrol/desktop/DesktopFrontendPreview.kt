package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.flow.MutableStateFlow

/** Explicit visual-fixture adapter only. Never used by normal startup and never executes effects. */
@Composable
internal fun DesktopVpnControlApp(windowProvider: () -> ComposeWindow, service: DesktopAppService,
    onCheckAndDownloadUpdate: () -> Unit, onDismissOrCancelUpdate: () -> Unit, onInstallUpdate: () -> Unit) {
    val client = remember(service) {
        val owner = "visual-preview"
        val snapshot = service.controlPresentationSnapshot(owner)
        val session = object : ControlSession {
            override val snapshots = MutableStateFlow(service.controlSnapshot(owner))
            override suspend fun submit(request: ControlRequest): ControlResult {
                if (request.command.operation == ControlOperationId.SETTINGS_SHOW) {
                    val read = service.controlSettingsSnapshot()
                    return ControlResult(owner, request.requestId, ControlCode.OK, read.metadata.configurationRevision, data = read.values)
                }
                if (request.command.operation in DesktopControlInspection.operations) {
                    val read = service.controlReadSnapshot(request.command)
                    return ControlResult(owner, request.requestId, read.code, read.metadata.configurationRevision,
                        data = read.values.getOrDefault(emptyMap()))
                }
                return ControlResult(owner, request.requestId, ControlCode.UNSUPPORTED, snapshot.configurationRevision)
            }
            override suspend fun operation(id: String): ControlOperation? = null
            override suspend fun cancelOperation(id: String) = ControlResult(owner, "preview-cancel", ControlCode.UNSUPPORTED, snapshot.configurationRevision)
        }
        DesktopFrontendClient(session, MutableStateFlow(snapshot), MutableStateFlow(null))
    }
    DesktopVpnControlApp(windowProvider, client, onCheckAndDownloadUpdate, onDismissOrCancelUpdate, onInstallUpdate,
        previewState = service.state)
}
