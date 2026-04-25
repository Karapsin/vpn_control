package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
                        text = "VPN Control",
                        color = Color.White,
                        fontSize = 34.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    headerActions()
                }
                Text(
                    text = if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                        "Subscription mode is active. Finding the best location downloads locations from the remote source and updates the saved list."
                    } else {
                        "Saved locations are active. Finding the best location tests the locations saved on the Locations tab."
                    },
                    color = Color(0xFFD3E3EE),
                )
                if (showSubscriptionMismatchWarning) {
                    SubscriptionMismatchWarningCard(activeProfileLabel = activeProfileLabel)
                }
                StatusCard(
                    state = state,
                    activeProfileLabel = activeProfileLabel,
                    extraDetails = statusDetails,
                )
                MainActionButton(
                    icon = powerIcon,
                    label = when {
                        state.appMode == AppMode.PROXY_ONLY && state.isVpnRunning -> "Stop Proxy"
                        state.appMode == AppMode.PROXY_ONLY -> "Start Proxy"
                        state.isVpnRunning -> "Disconnect"
                        else -> "Connect"
                    },
                    sublabel = when (state.appMode) {
                        AppMode.VPN -> if (state.hasVpnPermission) {
                            "Connect or disconnect the VPN"
                        } else {
                            "VPN permission required"
                        }
                        AppMode.PROXY_ONLY -> "Start or stop the local mixed proxy"
                    },
                    onClick = onToggleVpn,
                    enabled = !state.isBusy,
                    colors = if (state.isVpnRunning) activeVpnButtonColors() else darkButtonColors(),
                )
                MainActionButton(
                    icon = findBestIcon,
                    label = "Find Best",
                    sublabel = state.lastBenchmarkSummary.ifBlank {
                        if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                            "Find the best location from the subscription"
                        } else {
                            "Find the best location from saved locations"
                        }
                    },
                    onClick = onRefresh,
                    enabled = !state.isBusy,
                    outlined = true,
                )
                OutlinedButton(
                    onClick = onExportDiagnostics,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                        disabledContentColor = Color(0xFF94A9B8),
                    ),
                ) {
                    Text("Export Diagnostics")
                }
            }
        }
    }
}
