package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode

@Composable
fun MainScreen(
    state: MainUiState,
    activeProfileLabel: String,
    showSubscriptionMismatchWarning: Boolean,
    statusDetails: List<String> = emptyList(),
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
    powerIcon: ImageVector,
    findBestIcon: ImageVector,
    modifier: Modifier = Modifier,
    headerActions: @Composable () -> Unit = {},
) {
    val activeMode = state.profileSourceMode
    val strings = LocalAppStrings.current

    Scaffold(
        modifier = modifier,
        containerColor = Color(0xFF141F2D),
        contentColor = Color.White,
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 20.dp, top = 24.dp, end = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.Top,
                ) {
                    Text(
                        text = strings.get(UiText.APP_TITLE),
                        color = Color.White,
                        fontSize = 34.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Row { headerActions() }
                }
                Text(
                    text = if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                        strings.get(UiText.MAIN_SUBSCRIPTION_DESCRIPTION)
                    } else {
                        strings.get(UiText.MAIN_SAVED_LOCATIONS_DESCRIPTION)
                    },
                    color = Color(0xFFD3E3EE),
                )
                if (showSubscriptionMismatchWarning) {
                    SubscriptionMismatchWarningCard(
                        activeProfileLabel = activeProfileLabel,
                        modifier = Modifier.testTag("subscription-mismatch"),
                    )
                }
                StatusCard(
                    state = state,
                    activeProfileLabel = activeProfileLabel,
                    extraDetails = statusDetails,
                    modifier = Modifier.testTag("status"),
                )
                MainActionButton(
                    icon = powerIcon,
                    label = when {
                        state.appMode == AppMode.PROXY_ONLY && state.isVpnRunning -> strings.get(UiText.STOP_PROXY)
                        state.appMode == AppMode.PROXY_ONLY -> strings.get(UiText.START_PROXY)
                        state.isVpnRunning -> strings.get(UiText.DISCONNECT)
                        else -> strings.get(UiText.CONNECT)
                    },
                    sublabel = when (state.appMode) {
                        AppMode.VPN -> if (state.hasVpnPermission) {
                            strings.get(UiText.VPN_CONNECT_DESCRIPTION)
                        } else {
                            strings.get(UiText.VPN_PERMISSION_REQUIRED)
                        }
                        AppMode.PROXY_ONLY -> strings.get(UiText.PROXY_CONNECT_DESCRIPTION)
                    },
                    onClick = onToggleVpn,
                    enabled = !state.isBusy,
                    colors = if (state.isVpnRunning) activeVpnButtonColors() else darkButtonColors(),
                    visualId = when {
                        state.appMode == AppMode.PROXY_ONLY && state.isVpnRunning -> "stop-proxy"
                        state.appMode == AppMode.PROXY_ONLY -> "start-proxy"
                        state.isVpnRunning -> "disconnect"
                        else -> "connect"
                    },
                    sublabelVisualId = if (!state.hasVpnPermission && state.appMode == AppMode.VPN) {
                        "vpn-permission-required"
                    } else {
                        null
                    },
                )
                MainActionButton(
                    icon = findBestIcon,
                    label = strings.get(UiText.FIND_BEST),
                    sublabel = state.lastBenchmarkSummary.ifBlank {
                        if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                            strings.get(UiText.FIND_BEST_SUBSCRIPTION)
                        } else {
                            strings.get(UiText.FIND_BEST_SAVED)
                        }
                    },
                    onClick = onRefresh,
                    enabled = !state.isBusy,
                    outlined = true,
                    visualId = "find-best",
                )
                OutlinedButton(
                    onClick = onExportDiagnostics,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("export-diagnostics"),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                        disabledContentColor = Color(0xFF94A9B8),
                    ),
                ) {
                    Text(strings.get(UiText.EXPORT_DIAGNOSTICS))
                }
            }
        }
    }
}
