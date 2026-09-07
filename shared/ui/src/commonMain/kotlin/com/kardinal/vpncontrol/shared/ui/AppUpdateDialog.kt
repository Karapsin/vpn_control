package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.AppInstallSessionPhase

@Composable
fun AppUpdateDialog(
    state: AppUpdateState,
    onDismiss: () -> Unit,
    onRetry: () -> Unit,
    onInstall: () -> Unit,
    onOpenReleaseNotes: () -> Unit,
) {
    if (!state.showDialog) return
    val strings = LocalAppStrings.current
    val busy = (state.phase != AppUpdatePhase.INSTALLING || state.installSession == null) && state.phase in setOf(
        AppUpdatePhase.CHECKING,
        AppUpdatePhase.DOWNLOADING,
        AppUpdatePhase.VERIFYING,
        AppUpdatePhase.INSTALLING,
    )
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(strings.get(UiText.UPDATE_DIALOG_TITLE)) },
        text = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    if (state.phase == AppUpdatePhase.INSTALLING && state.installSession != null)
                        strings.format(UiText.SETTINGS_CURRENT_VERSION, state.currentVersion)
                    else updatePhaseText(state, strings),
                    modifier = Modifier.testTag(if (busy) "update-progress" else "update-message"),
                )
                state.installSession?.let { session ->
                    Text(strings.get(installSessionText(session.phase)), Modifier.testTag("update-install-session"))
                }
                if (state.phase == AppUpdatePhase.DOWNLOADING) {
                    state.progress?.let { progress ->
                        LinearProgressIndicator(
                            progress = { progress },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    } ?: LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                    Text("${formatUpdateBytes(state.downloadedBytes)} / ${formatUpdateBytes(state.totalBytes)}")
                }
                if (state.phase == AppUpdatePhase.READY) {
                    Text(strings.get(UiText.UPDATE_INSTALL_WARNING))
                }
                if (state.message.isNotBlank()) {
                    Text(updateDetailText(state.message, strings))
                }
                if (state.releaseNotesUrl.isNotBlank()) {
                    OutlinedButton(
                        onClick = onOpenReleaseNotes,
                        modifier = Modifier.heightIn(min = 48.dp).testTag("update-release-notes"),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = VpnControlColors.Accent),
                    ) {
                        Text(strings.get(UiText.UPDATE_RELEASE_NOTES))
                    }
                }
            }
        },
        confirmButton = {
            if (state.installSession?.resumable == true) Button(onClick = onInstall,
                modifier = Modifier.heightIn(min = 48.dp).testTag("update-install"), colors = darkButtonColors()) {
                Text(strings.get(UiText.UPDATE_INSTALL))
            } else when (state.phase) {
                AppUpdatePhase.READY -> Button(
                    onClick = onInstall,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("update-install"),
                    colors = darkButtonColors(),
                ) {
                    Text(strings.get(UiText.UPDATE_INSTALL))
                }
                AppUpdatePhase.FAILED,
                AppUpdatePhase.UNSUPPORTED,
                -> Button(
                    onClick = onRetry,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("update-retry"),
                    colors = darkButtonColors(),
                ) {
                    Text(strings.get(UiText.UPDATE_RETRY))
                }
                else -> Unit
            }
        },
        dismissButton = {
            OutlinedButton(
                onClick = onDismiss,
                enabled = state.phase != AppUpdatePhase.INSTALLING || state.installSession != null,
                modifier = Modifier
                    .padding(end = 4.dp)
                    .heightIn(min = 48.dp)
                    .testTag(if (busy) "update-cancel" else "update-close"),
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = VpnControlColors.Accent,
                    disabledContentColor = VpnControlColors.TextMuted,
                ),
            ) {
                Text(strings.get(if (busy) UiText.CANCEL else UiText.CLOSE))
            }
        },
    )
}

internal fun installSessionText(phase: AppInstallSessionPhase): UiText = when (phase) {
    AppInstallSessionPhase.PREPARING, AppInstallSessionPhase.STAGED, AppInstallSessionPhase.COMMITTING -> UiText.UPDATE_INSTALLING
    AppInstallSessionPhase.AWAITING_CONFIRMATION, AppInstallSessionPhase.HANDED_OFF -> UiText.UPDATE_INSTALL_CONFIRMATION
    AppInstallSessionPhase.INSTALLED -> UiText.UPDATE_INSTALL_COMPLETED
    AppInstallSessionPhase.FAILED -> UiText.UPDATE_FAILED
    AppInstallSessionPhase.UNKNOWN -> UiText.UPDATE_INSTALL_UNKNOWN
    AppInstallSessionPhase.CANCELLED -> UiText.UPDATE_INSTALL_CANCELLED
}

internal fun updateDetailText(message: String, strings: AppStrings): String = when (message) {
    "CANCELLED" -> strings.get(UiText.UPDATE_INSTALL_CANCELLED)
    "OUTCOME_UNKNOWN" -> strings.get(UiText.UPDATE_INSTALL_UNKNOWN)
    "INTERACTION_REQUIRED" -> strings.get(UiText.UPDATE_INSTALL_INTERACTION_REQUIRED)
    "PERMISSION_DENIED" -> strings.get(UiText.UPDATE_INSTALL_PERMISSION_DENIED)
    else -> message
}

private fun updatePhaseText(state: AppUpdateState, strings: AppStrings): String {
    return when (state.phase) {
        AppUpdatePhase.IDLE -> strings.format(UiText.SETTINGS_CURRENT_VERSION, state.currentVersion)
        AppUpdatePhase.CHECKING -> strings.get(UiText.UPDATE_CHECKING)
        AppUpdatePhase.DOWNLOADING -> strings.format(UiText.UPDATE_DOWNLOADING, state.availableVersion)
        AppUpdatePhase.VERIFYING -> strings.get(UiText.UPDATE_VERIFYING)
        AppUpdatePhase.READY -> strings.format(UiText.UPDATE_READY, state.availableVersion)
        AppUpdatePhase.UP_TO_DATE -> strings.format(UiText.UPDATE_UP_TO_DATE, state.currentVersion)
        AppUpdatePhase.INSTALLING -> strings.get(UiText.UPDATE_INSTALLING)
        AppUpdatePhase.UNSUPPORTED -> strings.get(UiText.UPDATE_UNSUPPORTED)
        AppUpdatePhase.FAILED -> strings.get(UiText.UPDATE_FAILED)
    }
}

private fun formatUpdateBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val mebibytes = bytes / (1024.0 * 1024.0)
    return if (mebibytes >= 1.0) {
        "${(mebibytes * 10).toLong() / 10.0} MiB"
    } else {
        "${bytes / 1024} KiB"
    }
}
