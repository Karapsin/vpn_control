package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.control.toControlValues
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.flow.MutableStateFlow

internal fun visualPreviewFrame(service: DesktopAppService, owner: String): Pair<ControlSnapshot, DesktopPresentationSnapshot> {
    val realRuntime = service.controlSnapshot(owner)
    val visualState = service.state
    // Visual scenes simulate connection state without starting sing-box. Keep the fixture's
    // runtime and statistics fields consistent so the normal strict frontend decoder applies.
    val previewRuntime = realRuntime.copy(
        runtimeRunning = visualState.isVpnRunning,
        activeMode = visualState.appMode.takeIf { visualState.isVpnRunning },
        activeLocationId = realRuntime.selectedLocationId.takeIf { visualState.isVpnRunning },
        runtimeStartedAt = visualState.sessionStartedAtEpochMillis.takeIf { visualState.isVpnRunning && it > 0 },
    )
    val frame = service.controlPresentationSnapshot(owner)
    val previewFrame = frame.copy(values = frame.values +
        ("runtime" to ControlValue.ObjectValue(previewRuntime.toControlValues())))
    return previewRuntime to previewFrame
}

/** Explicit visual-fixture adapter only. Never used by normal startup and never executes effects. */
@Composable
internal fun DesktopVpnControlApp(windowProvider: () -> ComposeWindow, service: DesktopAppService,
    onCheckAndDownloadUpdate: () -> Unit, onDismissOrCancelUpdate: () -> Unit, onInstallUpdate: () -> Unit) {
    val client = remember(service) {
        val owner = "visual-preview"
        val (runtimeSnapshot, snapshot) = visualPreviewFrame(service, owner)
        val session = object : ControlSession {
            override val snapshots = MutableStateFlow(runtimeSnapshot)
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
