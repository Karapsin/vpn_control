package com.kardinal.vpncontrol.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.InstalledApp
import java.util.Locale

@Composable
fun VpnControlApp(
    state: MainUiState,
    onToggleProfileDialog: () -> Unit,
    onProfileChange: (String) -> Unit,
    onSaveProfile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onDnsEnabledChange: (Boolean) -> Unit,
    onDnsChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onCloseRoutingRules: () -> Unit,
    onRoutingAppSearchChange: (String) -> Unit,
    onToggleProxyRoutingApp: (String) -> Unit,
    onToggleDirectRoutingApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
    onRoutingNationalDomainsChange: (String) -> Unit,
    onRoutingDirectDomainsChange: (String) -> Unit,
    onSaveRoutingRules: () -> Unit,
    onExportRoutingRules: () -> Unit,
    onImportRoutingRules: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
) {
    val background = Brush.verticalGradient(
        colors = listOf(Color(0xFF08111F), Color(0xFF12304B), Color(0xFF3D6B59)),
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(background),
    ) {
        when (state.currentScreen) {
            AppScreen.MAIN -> MainScreen(
                state = state,
                onToggleProfileDialog = onToggleProfileDialog,
                onToggleDnsDialog = onToggleDnsDialog,
                onOpenRoutingRules = onOpenRoutingRules,
                onToggleVpn = onToggleVpn,
                onRefresh = onRefresh,
                onExportDiagnostics = onExportDiagnostics,
            )
            AppScreen.ROUTING_RULES -> RoutingRulesScreen(
                state = state,
                onBack = onCloseRoutingRules,
                onAppSearchChange = onRoutingAppSearchChange,
                onToggleProxyApp = onToggleProxyRoutingApp,
                onToggleDirectApp = onToggleDirectRoutingApp,
                onSelectAllProxyApps = onSelectAllProxyApps,
                onClearAllProxyApps = onClearAllProxyApps,
                onSelectAllDirectApps = onSelectAllDirectApps,
                onClearAllDirectApps = onClearAllDirectApps,
                onNationalDomainsChange = onRoutingNationalDomainsChange,
                onDirectDomainsChange = onRoutingDirectDomainsChange,
                onSave = onSaveRoutingRules,
                onExport = onExportRoutingRules,
                onImport = onImportRoutingRules,
            )
        }
    }

    if (state.showProfileDialog) {
        AlertDialog(
            onDismissRequest = onToggleProfileDialog,
            title = { Text("Profile URL") },
            text = {
                OutlinedTextField(
                    value = state.profileDraft,
                    onValueChange = onProfileChange,
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    label = { Text("Subscription URL") },
                )
            },
            confirmButton = {
                TextButton(onClick = onSaveProfile) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleProfileDialog) {
                    Text("Cancel")
                }
            },
        )
    }

    if (state.showDnsDialog) {
        AlertDialog(
            onDismissRequest = onToggleDnsDialog,
            title = { Text("Custom DNS") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text("Use custom DNS")
                        Switch(
                            checked = state.useCustomDns,
                            onCheckedChange = onDnsEnabledChange,
                        )
                    }
                    OutlinedTextField(
                        value = state.customDnsDraft,
                        onValueChange = onDnsChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("DNS IP address") },
                        enabled = state.useCustomDns,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveDns) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleDnsDialog) {
                    Text("Cancel")
                }
            },
        )
    }
}

@Composable
private fun MainScreen(
    state: MainUiState,
    onToggleProfileDialog: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
) {
    Scaffold(
        containerColor = Color.Transparent,
        contentColor = Color.White,
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp, vertical = 24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text(
                    text = "VPN Control",
                    color = Color.White,
                    fontSize = 34.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "Subscription-driven Android controller for VLESS profiles.",
                    color = Color(0xFFD3E3EE),
                )

                StatusCard(state)

                ActionButton(
                    label = "Get Profile",
                    sublabel = state.profileUrl.ifBlank { "Enter subscription URL" },
                    onClick = onToggleProfileDialog,
                )
                ActionButton(
                    label = if (state.isVpnRunning) "Stop VPN" else "Start VPN",
                    sublabel = if (state.hasVpnPermission) "Toggle active tunnel" else "Requires VPN permission",
                    onClick = onToggleVpn,
                    enabled = !state.isBusy,
                )
                ActionButton(
                    label = "Refresh",
                    sublabel = state.lastBenchmarkSummary.ifBlank { "Select best location from subscription" },
                    onClick = onRefresh,
                    enabled = !state.isBusy,
                )
                ActionButton(
                    label = "Set Custom DNS",
                    sublabel = if (state.useCustomDns && state.customDns.isNotBlank()) state.customDns else "Use system DNS",
                    onClick = onToggleDnsDialog,
                )
                ActionButton(
                    label = "Routing Rules",
                    sublabel = routingSummary(state),
                    onClick = onOpenRoutingRules,
                    enabled = !state.isBusy,
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

@Composable
private fun RoutingRulesScreen(
    state: MainUiState,
    onBack: () -> Unit,
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onToggleDirectApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
    onNationalDomainsChange: (String) -> Unit,
    onDirectDomainsChange: (String) -> Unit,
    onSave: () -> Unit,
    onExport: () -> Unit,
    onImport: () -> Unit,
) {
    val query = state.routingAppSearch.trim().lowercase(Locale.ROOT)
    val filteredApps = state.installedApps
        .asSequence()
        .filter { app ->
            query.isBlank() ||
                app.label.contains(query, ignoreCase = true) ||
                app.packageName.contains(query, ignoreCase = true)
        }
        .sortedWith(
            compareBy<InstalledApp> { assignmentRank(it.packageName, state) }
                .thenBy { it.isSystemApp }
                .thenBy { it.label.lowercase(Locale.ROOT) },
        )
        .toList()

    Scaffold(
        containerColor = Color.Transparent,
        contentColor = Color.White,
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp, vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 18.dp),
        ) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    OutlinedButton(
                        onClick = onBack,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Text("Back")
                    }
                    Button(
                        onClick = onSave,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Text("Save")
                    }
                }
            }
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    OutlinedButton(
                        onClick = onImport,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Text("Import")
                    }
                    OutlinedButton(
                        onClick = onExport,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Text("Export")
                    }
                }
            }
            item {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(
                        text = "Routing Rules",
                        color = Color.White,
                        fontSize = 28.sp,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        text = "Apps in the direct list bypass the VPN. Domain suffixes stay on your normal connection.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 14.sp,
                    )
                }
            }
            item {
                CompactSummaryCard(state)
            }
            item {
                AppSelectionSectionCard(
                    title = "Proxy Apps",
                    count = state.routingProxyPackagesDraft.size,
                    description = "If this list is not empty, only these apps use the VPN. National and custom domain rules still go direct.",
                    onSelectAll = onSelectAllProxyApps,
                    onClearAll = onClearAllProxyApps,
                    enableSelectAll = !state.installedAppsLoading && filteredApps.isNotEmpty(),
                    enableClearAll = !state.installedAppsLoading && state.routingProxyPackagesDraft.isNotEmpty(),
                )
            }
            item {
                AppSelectionSectionCard(
                    title = "Direct Apps",
                    count = state.routingBypassPackagesDraft.size,
                    description = "These apps stay off the VPN. An app cannot be both direct and proxy.",
                    onSelectAll = onSelectAllDirectApps,
                    onClearAll = onClearAllDirectApps,
                    enableSelectAll = !state.installedAppsLoading && filteredApps.isNotEmpty(),
                    enableClearAll = !state.installedAppsLoading && state.routingBypassPackagesDraft.isNotEmpty(),
                )
            }
            item {
                RuleTextField(
                    title = "National Domains",
                    description = "One per line. Example: ru",
                    value = state.routingNationalDomainsDraft,
                    onValueChange = onNationalDomainsChange,
                )
            }
            item {
                RuleTextField(
                    title = "Direct Domains",
                    description = "One per line. Example: karapsin.com",
                    value = state.routingDirectDomainsDraft,
                    onValueChange = onDirectDomainsChange,
                )
            }
            item {
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 14.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text("App Assignments", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                            Text(
                                "${filteredApps.size} shown",
                                color = Color(0xFFD3E3EE),
                                fontSize = 12.sp,
                            )
                        }
                        OutlinedTextField(
                            value = state.routingAppSearch,
                            onValueChange = onAppSearchChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Search apps or packages") },
                            singleLine = true,
                            colors = routingTextFieldColors(),
                        )
                        Text(
                            text = "Tap Proxy or Direct on an app row. Unassigned apps stay at the top.",
                            color = Color(0xFFD3E3EE),
                            fontSize = 12.sp,
                        )
                    }
                }
            }
            item {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(320.dp),
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                ) {
                    when {
                        state.installedAppsLoading -> {
                            Box(
                                modifier = Modifier.fillMaxSize(),
                                contentAlignment = Alignment.Center,
                            ) {
                                CircularProgressIndicator(color = Color.White)
                            }
                        }
                        filteredApps.isEmpty() -> {
                            Box(
                                modifier = Modifier
                                    .fillMaxSize()
                                    .padding(18.dp),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(
                                    text = if (state.installedAppsLoaded) {
                                        "No apps match the current search."
                                    } else {
                                        "Installed apps have not loaded yet."
                                    },
                                    color = Color(0xFFD3E3EE),
                                )
                            }
                        }
                        else -> {
                            LazyColumn(
                                modifier = Modifier.fillMaxSize(),
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                items(filteredApps, key = { it.packageName }) { app ->
                                    AppAssignmentRow(
                                        app = app,
                                        isProxy = app.packageName in state.routingProxyPackagesDraft,
                                        isDirect = app.packageName in state.routingBypassPackagesDraft,
                                        onToggleProxy = { onToggleProxyApp(app.packageName) },
                                        onToggleDirect = { onToggleDirectApp(app.packageName) },
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactSummaryCard(state: MainUiState) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text("Current Rules", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            Text(
                "${state.routingProxyPackagesDraft.size} proxy apps • ${state.routingBypassPackagesDraft.size} direct apps",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "${state.routingNationalDomainsDraft.countEntries()} national suffixes • " +
                    "${state.routingDirectDomainsDraft.countEntries()} direct domains",
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            if (state.isVpnRunning) {
                Text(
                    text = "Restart the VPN after saving or importing rules.",
                    color = Color(0xFFFFE0A3),
                    fontSize = 12.sp,
                )
            }
        }
    }
}

@Composable
private fun AppSelectionSectionCard(
    title: String,
    count: Int,
    description: String,
    onSelectAll: () -> Unit,
    onClearAll: () -> Unit,
    enableSelectAll: Boolean,
    enableClearAll: Boolean,
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text("$count selected", color = Color(0xFFD3E3EE), fontSize = 12.sp)
            }
            Text(description, color = Color(0xFFD3E3EE), fontSize = 12.sp)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onSelectAll,
                    enabled = enableSelectAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Select All")
                }
                OutlinedButton(
                    onClick = onClearAll,
                    enabled = enableClearAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                ) {
                    Text("Clear All")
                }
            }
        }
    }
}

@Composable
private fun RuleTextField(
    title: String,
    description: String,
    value: String,
    onValueChange: (String) -> Unit,
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(title, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(description, color = Color(0xFFD3E3EE), fontSize = 12.sp)
            OutlinedTextField(
                value = value,
                onValueChange = onValueChange,
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                colors = routingTextFieldColors(),
            )
        }
    }
}

@Composable
private fun AppAssignmentRow(
    app: InstalledApp,
    isProxy: Boolean,
    isDirect: Boolean,
    onToggleProxy: () -> Unit,
    onToggleDirect: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isProxy -> Color(0x333983FF)
                isDirect -> Color(0x3349C089)
                else -> Color(0x1F203041)
            },
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(1.dp),
            ) {
                Text(
                    text = app.label,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = app.packageName,
                    color = Color(0xFFD3E3EE),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    OutlinedButton(
                        onClick = onToggleProxy,
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = if (isProxy) "Proxy On" else "Proxy",
                            color = if (isProxy) Color(0xFF83B7FF) else Color.Unspecified,
                            fontSize = 11.sp,
                        )
                    }
                    OutlinedButton(
                        onClick = onToggleDirect,
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                    ) {
                        Text(
                            text = if (isDirect) "Direct On" else "Direct",
                            color = if (isDirect) Color(0xFF7FE7B5) else Color.Unspecified,
                            fontSize = 11.sp,
                        )
                    }
                }
                if (app.isSystemApp) {
                    Text(
                        text = "sys",
                        color = Color(0xFF9ED6FF),
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusCard(state: MainUiState) {
    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text("Status", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(state.statusMessage, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            if (state.selectedProfileName.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text("Selected: ${state.selectedProfileName}", color = Color(0xFFD3E3EE))
                Text("Server: ${state.selectedProfileServer}", color = Color(0xFFD3E3EE))
            }
        }
    }
}

@Composable
private fun ActionButton(
    label: String,
    sublabel: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(18.dp),
        shape = RoundedCornerShape(22.dp),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(label, fontSize = 22.sp, fontWeight = FontWeight.Bold)
            Text(sublabel)
        }
    }
}

private fun routingSummary(state: MainUiState): String {
    return buildString {
        append("${state.routingRules.proxyPackages.size} proxy")
        append(" • ")
        append("${state.routingRules.bypassPackages.size} direct")
        append(" • ")
        append("${state.routingRules.nationalDomainSuffixes.size} national suffixes")
        append(" • ")
        append("${state.routingRules.directDomainSuffixes.size} custom domains")
    }
}

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        packageName in state.routingBypassPackagesDraft -> 1
        else -> 2
    }
}

@Composable
private fun routingTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color.White,
    unfocusedTextColor = Color.White,
    disabledTextColor = Color(0xFFD3E3EE),
    cursorColor = Color(0xFF9ED6FF),
    focusedBorderColor = Color(0xFF9ED6FF),
    unfocusedBorderColor = Color(0xFF5F7D92),
    focusedLabelColor = Color(0xFF9ED6FF),
    unfocusedLabelColor = Color(0xFFD3E3EE),
    focusedPlaceholderColor = Color(0xFF9FB8C8),
    unfocusedPlaceholderColor = Color(0xFF9FB8C8),
)

private fun String.countEntries(): Int {
    return split(Regex("[,\\n\\r\\t ]+"))
        .map { it.trim() }
        .count { it.isNotBlank() }
}
