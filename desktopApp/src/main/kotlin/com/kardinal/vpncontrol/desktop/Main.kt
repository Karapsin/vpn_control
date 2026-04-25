package com.kardinal.vpncontrol.desktop

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QueryStats
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.awt.ComposeWindow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.shared.ui.HomeTabScaffold
import com.kardinal.vpncontrol.shared.ui.LocationsScreen
import com.kardinal.vpncontrol.shared.ui.MainScreen
import com.kardinal.vpncontrol.shared.ui.ProfileScreen
import com.kardinal.vpncontrol.shared.ui.RoutingRulesScreen
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow
import com.kardinal.vpncontrol.shared.ui.StatsScreen
import com.kardinal.vpncontrol.shared.ui.activeProfileLabel
import com.kardinal.vpncontrol.shared.ui.currentSubscriptionSelectionLabel
import com.kardinal.vpncontrol.shared.ui.formatLocationCountLabel
import com.kardinal.vpncontrol.shared.ui.selectedLocationOutsideCurrentSubscription
import kotlinx.coroutines.launch

fun main() = application {
    val service = remember { DesktopAppService.default() }
    val coroutineScope = rememberCoroutineScope()
    val traySupported = remember { isDesktopTraySupported() }
    var windowVisible by remember { mutableStateOf(true) }
    val state = service.state

    if (traySupported) {
        DesktopTrayIcon(
            connectionActionLabel = trayConnectionActionLabel(state),
            connectionActionEnabled = !state.isBusy,
            findBestEnabled = !state.isBusy,
            onToggleConnection = {
                if (!service.state.isBusy) {
                    coroutineScope.launch { service.toggleSelectedLocationProxy() }
                }
            },
            onFindBest = {
                if (!service.state.isBusy) {
                    coroutineScope.launch { service.findBestLocation() }
                }
            },
            onShowWindow = { windowVisible = true },
            onHideWindow = { windowVisible = false },
            onExit = ::exitApplication,
        )
    }

    Window(
        visible = windowVisible,
        onCloseRequest = {
            if (traySupported) {
                windowVisible = false
            } else {
                exitApplication()
            }
        },
        title = "VPN Control Desktop",
    ) {
        LaunchedEffect(windowVisible) {
            if (windowVisible) {
                window.toFront()
                window.requestFocus()
            }
        }
        MaterialTheme(
            colorScheme = darkColorScheme(
                background = Color(0xFF08111F),
                surface = Color(0xFF141F2D),
                primary = Color(0xFF4B7BE5),
                secondary = Color(0xFF9ED6FF),
            ),
        ) {
            Surface(color = Color.Transparent) {
                DesktopVpnControlApp(window, service)
            }
        }
    }
}

@Composable
private fun DesktopVpnControlApp(
    window: ComposeWindow,
    service: DesktopAppService,
) {
    val coroutineScope = rememberCoroutineScope()
    val autoRefreshScheduler = remember { DesktopAutoRefreshScheduler(service, coroutineScope) }
    val state = service.state
    val activeProfile = activeProfileLabel(state, service::sourceLabelFor)
    val currentSelection = currentSubscriptionSelectionLabel(state, service::sourceLabelFor)
    val showMismatchWarning = selectedLocationOutsideCurrentSubscription(state)

    LaunchedEffect(
        state.profileSourceMode,
        state.subscriptionRefreshPolicy,
        state.subscriptionRefreshCustomHours,
        state.subscriptions,
    ) {
        autoRefreshScheduler.sync(state)
    }

    DisposableEffect(Unit) {
        onDispose {
            autoRefreshScheduler.cancel()
        }
    }

    DesktopSettingsDialogs(
        state = state,
        onToggleDnsDialog = service::toggleDnsDialog,
        onUseCustomDnsDraftChange = service::setUseCustomDnsDraft,
        onCustomDnsDraftChange = service::setCustomDnsDraft,
        onSaveDns = service::saveDns,
        onToggleAppModeDialog = service::toggleAppModeDialog,
        onSetAppMode = { mode ->
            if (!state.isBusy) {
                coroutineScope.launch { service.setAppMode(mode) }
            }
        },
        onToggleRefreshPolicyDialog = service::toggleRefreshPolicyDialog,
        onSubscriptionRefreshPolicyDraftChange = service::setSubscriptionRefreshPolicyDraft,
        onFindBestAfterSubscriptionRefreshDraftChange = service::setFindBestAfterSubscriptionRefreshDraft,
        onSubscriptionRefreshCustomHoursDraftChange = service::setSubscriptionRefreshCustomHoursDraft,
        onSaveSubscriptionRefreshPolicy = service::saveSubscriptionRefreshPolicy,
        onToggleValidationSettingsDialog = service::toggleValidationSettingsDialog,
        onValidationPrimaryUrlDraftChange = service::setValidationPrimaryUrlDraft,
        onValidationSecondaryUrlDraftChange = service::setValidationSecondaryUrlDraft,
        onValidationBatchSizeDraftChange = service::setValidationBatchSizeDraft,
        onValidationRetryCountDraftChange = service::setValidationRetryCountDraft,
        onSaveValidationSettings = service::saveValidationSettings,
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0xFF08111F), Color(0xFF12304B), Color(0xFF3D6B59)),
                ),
            ),
    ) {
        HomeTabScaffold(
            currentScreen = state.currentScreen,
            onOpenMainTab = { service.openScreen(AppScreen.MAIN) },
            onOpenProfileTab = { service.openScreen(AppScreen.PROFILE) },
            onOpenLocationsTab = { service.openScreen(AppScreen.LOCATIONS) },
            onOpenStatsTab = { service.openScreen(AppScreen.STATS) },
            onOpenRoutingRules = { service.openScreen(AppScreen.ROUTING_RULES) },
            mainIcon = Icons.Filled.Home,
            profileIcon = Icons.Filled.Person,
            locationsIcon = Icons.Filled.Public,
            statsIcon = Icons.Filled.QueryStats,
            rulesIcon = Icons.Filled.Tune,
        ) {
            when (state.currentScreen) {
                AppScreen.MAIN -> MainScreen(
                    state = state,
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    statusDetails = service.runtimeStatusDetails(),
                    onToggleVpn = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { service.toggleSelectedLocationProxy() }
                    },
                    onRefresh = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { service.findBestLocation() }
                    },
                    onExportDiagnostics = {
                        if (state.isBusy) return@MainScreen
                        val selection = DesktopTextTransfer.chooseSaveFile(
                            window = window,
                            title = "Export Diagnostics",
                            suggestedFileName = DesktopDiagnosticsExporter.suggestedFileName(),
                        )
                        coroutineScope.launch { service.exportDiagnostics(selection) }
                    },
                    powerIcon = Icons.Filled.PowerSettingsNew,
                    findBestIcon = Icons.Filled.MyLocation,
                    headerActions = {
                        DesktopAdditionalSettingsMenu(
                            state = state,
                            onToggleDnsDialog = service::toggleDnsDialog,
                            onSetStartOnBootEnabled = service::setStartOnBootEnabled,
                            onToggleAppModeDialog = service::toggleAppModeDialog,
                            onToggleRefreshPolicyDialog = service::toggleRefreshPolicyDialog,
                            onToggleValidationSettingsDialog = service::toggleValidationSettingsDialog,
                        )
                    },
                )

                AppScreen.PROFILE -> ProfileScreen(
                    activeProfileLabel = activeProfile,
                    currentSelectionLabel = currentSelection,
                ) {
                    DesktopProfileContent(
                        state = state,
                        resolveSourceLabel = service::sourceLabelFor,
                        onActivateSelection = service::activateSelection,
                        onSetSourceMode = service::setSourceMode,
                        onToggleAddSubscriptionEditor = service::toggleAddSubscriptionEditor,
                        onProfileDraftChange = service::setProfileDraft,
                        onClearProfileDraft = service::clearProfileDraft,
                        onSaveSubscriptionDraft = service::saveSubscriptionDraft,
                        onDeleteSubscription = { subscriptionId ->
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.deleteSubscription(subscriptionId) }
                        },
                        onShowSubscriptionRenameDialog = service::showSubscriptionRenameDialog,
                        onCloseSubscriptionRenameDialog = service::closeSubscriptionRenameDialog,
                        onSubscriptionRenameDraftChange = service::setSubscriptionRenameDraft,
                        onSaveSubscriptionRename = service::saveSubscriptionRename,
                        onRefreshActiveSubscriptions = {
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.refreshActiveSubscriptions() }
                        },
                        onRefreshAllSubscriptions = {
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.refreshAllSubscriptions() }
                        },
                    )
                }

                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    locations = service.visibleDesktopLocations().map { it.toSharedRow() },
                    selectedName = state.selectedProfileName.takeIf(String::isNotBlank),
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    onShowAddLocation = if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) ({
                        service.addSampleLocation()
                    }) else null,
                    onToggleSelectedLocationVpn = {
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.toggleSelectedLocationProxy() }
                    },
                    onBenchmarkLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.benchmarkLocation(index) }
                    },
                    onSelectLocation = { index -> service.applyLocationSelection(index) },
                    onEditLocation = { index -> service.editLocation(index) },
                    onDeleteLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.deleteLocation(index) }
                    },
                    controls = {
                        DesktopActionRow(
                            onImportFile = {
                                val selection = DesktopTextTransfer.chooseOpenFile(
                                    window = window,
                                    title = "Import Locations",
                                )
                                coroutineScope.launch { service.importLocationsFromFile(selection) }
                            },
                            onImportClipboard = { coroutineScope.launch { service.importLocationsFromClipboard() } },
                            onExportFile = { service.exportLocationsToFile(window) },
                            onExportClipboard = service::exportLocationsToClipboard,
                        )
                    },
                )

                AppScreen.ROUTING_RULES -> RoutingRulesScreen(
                    state = state,
                    onIgnoreRulesChange = service::setRoutingIgnoreRulesDraft,
                    onAppSearchChange = service::setRoutingAppSearch,
                    onToggleProxyApp = service::toggleProxyApp,
                    onSelectAllProxyApps = service::selectAllProxyApps,
                    onClearAllProxyApps = service::clearAllProxyApps,
                    onNationalDomainsChange = service::setRoutingNationalDomainsDraft,
                    onDirectDomainsChange = service::setRoutingDirectDomainsDraft,
                    onSave = service::saveRoutingRules,
                    showAppAssignments = false,
                    controls = {
                        DesktopActionRow(
                            onImportFile = { service.importRoutingRulesFromFile(window) },
                            onImportClipboard = service::importRoutingRulesFromClipboard,
                            onExportFile = { service.exportRoutingRulesToFile(window) },
                            onExportClipboard = service::exportRoutingRulesToClipboard,
                        )
                    },
                )

                AppScreen.STATS -> StatsScreen(state = state)
            }
        }
    }
}

private fun trayConnectionActionLabel(state: MainUiState): String {
    return when (state.appMode) {
        AppMode.VPN -> if (state.isVpnRunning) "Stop VPN" else "Start VPN"
        AppMode.PROXY_ONLY -> if (state.isVpnRunning) "Stop Proxy" else "Start Proxy"
    }
}

@Composable
private fun DesktopProfileContent(
    state: MainUiState,
    resolveSourceLabel: (String) -> String,
    onActivateSelection: (String) -> Unit,
    onSetSourceMode: (ProfileSourceMode) -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onProfileDraftChange: (String) -> Unit,
    onClearProfileDraft: () -> Unit,
    onSaveSubscriptionDraft: () -> Unit,
    onDeleteSubscription: (String) -> Unit,
    onShowSubscriptionRenameDialog: (String) -> Unit,
    onCloseSubscriptionRenameDialog: () -> Unit,
    onSubscriptionRenameDraftChange: (String) -> Unit,
    onSaveSubscriptionRename: () -> Unit,
    onRefreshActiveSubscriptions: () -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
) {
    if (state.showProfileHistoryRenameDialog) {
        AlertDialog(
            onDismissRequest = onCloseSubscriptionRenameDialog,
            confirmButton = {
                TextButton(onClick = onSaveSubscriptionRename) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseSubscriptionRenameDialog) {
                    Text("Cancel")
                }
            },
            title = {
                Text("Rename subscription")
            },
            text = {
                OutlinedTextField(
                    value = state.profileHistoryRenameDraft,
                    onValueChange = onSubscriptionRenameDraftChange,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Subscription name") },
                    placeholder = { Text("Optional custom name") },
                    singleLine = true,
                )
            },
        )
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("Desktop Shell", color = Color.White, style = MaterialTheme.typography.titleMedium)
                Text(
                    "This desktop target persists its workspace, supports file and clipboard import-export for locations and routing rules, refreshes direct https subscriptions, and starts sing-box in Proxy-only or desktop VPN mode.",
                    color = Color(0xFFD3E3EE),
                )
                Text(
                    "Auto-refresh while open: ${state.subscriptionRefreshPolicy.displayValue(state.subscriptionRefreshCustomHours)}",
                    color = Color(0xFF9ED6FF),
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(0.78f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                "Subscription Mode"
                            } else {
                                "Saved Locations"
                            },
                            color = Color.White,
                        )
                        Text(
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                "Turn off to work only with locations saved on the Locations tab."
                            } else {
                                "Turn on to use subscription-backed locations."
                            },
                            color = Color(0xFFD3E3EE),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Switch(
                        checked = state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION,
                        onCheckedChange = { enabled ->
                            onSetSourceMode(
                                if (enabled) {
                                    ProfileSourceMode.SUBSCRIPTION
                                } else {
                                    ProfileSourceMode.CURRENT_LOCATIONS
                                },
                            )
                        },
                    )
                }
            }
        }

        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
        ) {
            val selectedContainerColor = Color(0x263C7AE6)
            val selectedBorderColor = Color(0xFF9ED6FF)
            val normalContainerColor = Color.Transparent
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    "Subscriptions",
                    color = Color.White,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    fontSize = 22.sp,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    OutlinedButton(
                        onClick = onRefreshActiveSubscriptions,
                        enabled = !state.isBusy,
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White,
                            disabledContentColor = Color(0xFF9FB8C8),
                        ),
                    ) {
                        Text("Refresh Active")
                    }
                    OutlinedButton(
                        onClick = onRefreshAllSubscriptions,
                        enabled = !state.isBusy,
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White,
                            disabledContentColor = Color(0xFF9FB8C8),
                        ),
                    ) {
                        Text("Refresh All")
                    }
                }
                if (state.subscriptions.size > 1) {
                    val allSelected = state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onActivateSelection(ALL_SUBSCRIPTIONS_ID) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (allSelected) Color(0x334B7BE5) else Color(0x1B213246),
                        ),
                        border = if (allSelected) BorderStroke(1.dp, selectedBorderColor) else null,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(42.dp)
                                    .background(Color(0x223C7AE6), RoundedCornerShape(14.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Public,
                                    contentDescription = "All subscriptions",
                                    tint = Color.White,
                                )
                            }
                            Column(
                                modifier = Modifier.fillMaxWidth(0.82f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    "ALL • ${
                                        formatLocationCountLabel(
                                            state.subscriptions.sumOf { it.cachedLocations.size },
                                            merged = true,
                                        )
                                    }",
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                )
                                Text(
                                    "Merge locations from every saved subscription and search across all of them.",
                                    color = if (allSelected) selectedBorderColor else Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            if (allSelected) {
                                Box(
                                    modifier = Modifier
                                        .background(Color(0xFF2B4F7C), RoundedCornerShape(999.dp))
                                        .padding(horizontal = 12.dp, vertical = 6.dp),
                                ) {
                                    Text(
                                        "Active",
                                        color = Color.White,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                            }
                        }
                    }
                }
                state.subscriptions.forEach { subscription ->
                    val isSelected = state.activeSubscriptionId == subscription.id
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onActivateSelection(subscription.id) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected) selectedContainerColor else normalContainerColor,
                        ),
                        border = if (isSelected) BorderStroke(1.dp, selectedBorderColor) else null,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Top,
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(0.84f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    resolveSourceLabel(subscription.url),
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                )
                                if (isSelected) {
                                    Text(
                                        "Selected subscription",
                                        color = selectedBorderColor,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                                Text(
                                    "${formatLocationCountLabel(subscription.cachedLocations.size)} • ${subscription.lastRefreshStatus.ifBlank { "not refreshed yet" }}",
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                                IconButton(onClick = { onShowSubscriptionRenameDialog(subscription.id) }) {
                                    Icon(
                                        imageVector = Icons.Filled.Edit,
                                        contentDescription = "Rename subscription",
                                        tint = Color.White,
                                    )
                                }
                                IconButton(onClick = { onDeleteSubscription(subscription.id) }) {
                                    Icon(
                                        imageVector = Icons.Filled.Delete,
                                        contentDescription = "Delete subscription",
                                        tint = Color(0xFFFFA6A6),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            if (state.showAddSubscriptionEditor) {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x1C3C7AE6)),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                "Add a subscription",
                                color = Color.White,
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                IconButton(onClick = onClearProfileDraft) {
                                    Icon(
                                        imageVector = Icons.Filled.DeleteSweep,
                                        contentDescription = "Clear subscription draft",
                                        tint = Color.White,
                                    )
                                }
                                IconButton(onClick = onToggleAddSubscriptionEditor) {
                                    Icon(
                                        imageVector = Icons.Filled.Close,
                                        contentDescription = "Close add subscription editor",
                                        tint = Color.White,
                                    )
                                }
                            }
                        }
                        OutlinedTextField(
                            value = state.profileDraft,
                            onValueChange = onProfileDraftChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Subscription URL") },
                            placeholder = { Text("https://example.com/subscription.txt") },
                            singleLine = true,
                        )
                        Text(
                            "Desktop currently supports direct https:// subscription URLs here.",
                            color = Color(0xFFD3E3EE),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(onClick = onSaveSubscriptionDraft) {
                            Text("Save Subscription")
                        }
                    }
                }
            } else {
                DesktopAddSubscriptionLauncherCard(
                    onClick = onToggleAddSubscriptionEditor,
                )
            }
        }
    }
}

@Composable
private fun DesktopAdditionalSettingsMenu(
    state: MainUiState,
    onToggleDnsDialog: () -> Unit,
    onSetStartOnBootEnabled: (Boolean) -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val refreshScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
        "all subscriptions"
    } else {
        "selected subscription"
    }

    Box {
        OutlinedButton(
            onClick = { expanded = true },
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
        ) {
            Icon(
                imageVector = Icons.Filled.Settings,
                contentDescription = "Additional settings",
                modifier = Modifier.size(18.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Custom DNS")
                        Text(
                            if (state.useCustomDns) state.customDns.ifBlank { "enabled" } else "disabled",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleDnsDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Start on Login")
                        Text(
                            if (state.startOnBootEnabled) "enabled" else "disabled",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = state.startOnBootEnabled,
                        onCheckedChange = { enabled ->
                            expanded = false
                            onSetStartOnBootEnabled(enabled)
                        },
                    )
                },
                onClick = {
                    expanded = false
                    onSetStartOnBootEnabled(!state.startOnBootEnabled)
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("VPN / Proxy Mode")
                        Text(
                            if (state.appMode == AppMode.VPN) "VPN mode" else "Proxy-only mode",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleAppModeDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Subscription Auto-Refresh")
                        Text(
                            "${state.subscriptionRefreshPolicy.displayValue(state.subscriptionRefreshCustomHours)} • $refreshScope",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleRefreshPolicyDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text("Location Test Settings")
                        Text(
                            state.validationSettings.displaySummary(),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleValidationSettingsDialog()
                },
            )
        }
    }
}

@Composable
private fun DesktopSettingsDialogs(
    state: MainUiState,
    onToggleDnsDialog: () -> Unit,
    onUseCustomDnsDraftChange: (Boolean) -> Unit,
    onCustomDnsDraftChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onSetAppMode: (AppMode) -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyDraftChange: (SubscriptionRefreshPolicy) -> Unit,
    onFindBestAfterSubscriptionRefreshDraftChange: (Boolean) -> Unit,
    onSubscriptionRefreshCustomHoursDraftChange: (String) -> Unit,
    onSaveSubscriptionRefreshPolicy: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationPrimaryUrlDraftChange: (String) -> Unit,
    onValidationSecondaryUrlDraftChange: (String) -> Unit,
    onValidationBatchSizeDraftChange: (String) -> Unit,
    onValidationRetryCountDraftChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
) {
    if (state.showDnsDialog) {
        AlertDialog(
            onDismissRequest = onToggleDnsDialog,
            title = { Text("Custom DNS", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(
                            modifier = Modifier.fillMaxWidth(0.76f),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text("Use custom DNS", color = Color.White)
                            Text(
                                "Applies to new desktop proxy or VPN sessions.",
                                color = Color(0xFFD3E3EE),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Switch(
                            checked = state.useCustomDnsDraft,
                            onCheckedChange = onUseCustomDnsDraftChange,
                        )
                    }
                    OutlinedTextField(
                        value = state.customDnsDraft,
                        onValueChange = onCustomDnsDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("DNS IP address") },
                        placeholder = { Text("1.1.1.1") },
                        enabled = state.useCustomDnsDraft,
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveDns) {
                    Text("Save", color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleDnsDialog) {
                    Text("Cancel", color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showAppModeDialog) {
        AlertDialog(
            onDismissRequest = onToggleAppModeDialog,
            title = { Text("VPN / Proxy Mode", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "VPN mode uses sing-box TUN on Linux or Windows. Windows VPN mode requires running VPN Control as Administrator.",
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Card(
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(0.76f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = if (state.appMode == AppMode.VPN) "VPN Mode" else "Proxy-only",
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.appMode == AppMode.VPN) {
                                        "Turn off to use only the local proxy."
                                    } else {
                                        "Turn on to route desktop traffic through VPN/TUN mode."
                                    },
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Switch(
                                checked = state.appMode == AppMode.VPN,
                                onCheckedChange = { enabled ->
                                    onSetAppMode(
                                        if (enabled) {
                                            AppMode.VPN
                                        } else {
                                            AppMode.PROXY_ONLY
                                        },
                                    )
                                },
                            )
                        }
                    }
                    Text(
                        text = "Changing mode while connected stops the current session first.",
                        color = Color(0xFF9BB3C6),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = onToggleAppModeDialog) {
                    Text("Close", color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showRefreshPolicyDialog) {
        val refreshTarget = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
            "every saved subscription"
        } else {
            "the selected subscription"
        }
        AlertDialog(
            onDismissRequest = onToggleRefreshPolicyDialog,
            title = { Text("Subscription Auto-Refresh", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(
                        text = "While the desktop app is open, it can periodically redownload $refreshTarget and update cached locations.",
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    listOf(
                        SubscriptionRefreshPolicy.OFF,
                        SubscriptionRefreshPolicy.EVERY_HOUR,
                        SubscriptionRefreshPolicy.CUSTOM,
                    ).forEach { policy ->
                        DesktopSettingsOption(
                            title = policy.title,
                            description = when (policy) {
                                SubscriptionRefreshPolicy.OFF -> "Do not update subscriptions in the background."
                                SubscriptionRefreshPolicy.EVERY_HOUR -> "Refresh cached locations every hour."
                                SubscriptionRefreshPolicy.CUSTOM -> "Use a custom interval in hours. Minimum 5 minutes."
                            },
                            selected = state.subscriptionRefreshPolicyDraft == policy,
                            onClick = { onSubscriptionRefreshPolicyDraftChange(policy) },
                        )
                    }
                    Card(
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(
                                modifier = Modifier.fillMaxWidth(0.76f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = if (state.findBestAfterSubscriptionRefreshDraft) {
                                        "Find best after refresh"
                                    } else {
                                        "Keep current location after refresh"
                                    },
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = "When already connected, rerun best-location search after auto-refresh completes.",
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Switch(
                                checked = state.findBestAfterSubscriptionRefreshDraft,
                                onCheckedChange = onFindBestAfterSubscriptionRefreshDraftChange,
                            )
                        }
                    }
                    if (state.subscriptionRefreshPolicyDraft == SubscriptionRefreshPolicy.CUSTOM) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedTextField(
                                value = state.subscriptionRefreshCustomHoursDraft,
                                onValueChange = onSubscriptionRefreshCustomHoursDraftChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Custom interval (hours)") },
                                placeholder = { Text("0.5") },
                                singleLine = true,
                            )
                            Text(
                                text = "Examples: 0.5 = 30 minutes, 1.5 = 1 h 30 min. Minimum 5 minutes.",
                                color = Color(0xFF9BB3C6),
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveSubscriptionRefreshPolicy) {
                    Text("Save", color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleRefreshPolicyDialog) {
                    Text("Cancel", color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showValidationSettingsDialog) {
        val searchScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
            "all subscriptions"
        } else {
            "the selected subscription"
        }
        AlertDialog(
            onDismissRequest = onToggleValidationSettingsDialog,
            title = { Text("Location Test Settings", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        text = "Find best uses these sites when testing locations from $searchScope.",
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = state.validationPrimaryUrlDraft,
                        onValueChange = onValidationPrimaryUrlDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Primary test site") },
                        placeholder = { Text("google.com or full URL") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationSecondaryUrlDraft,
                        onValueChange = onValidationSecondaryUrlDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Secondary test site") },
                        placeholder = { Text("secondary-site.com or full URL") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationBatchSizeDraft,
                        onValueChange = onValidationBatchSizeDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Batch size") },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationRetryCountDraft,
                        onValueChange = onValidationRetryCountDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Retry count") },
                        placeholder = { Text("1") },
                        singleLine = true,
                    )
                    Text(
                        text = "Concurrency matches batch size, up to 5. Current: ${state.validationSettings.displaySummary()}",
                        color = Color(0xFF9ED6FF),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveValidationSettings) {
                    Text("Save", color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleValidationSettingsDialog) {
                    Text("Cancel", color = Color(0xFFD3E3EE))
                }
            },
        )
    }
}

@Composable
private fun DesktopSettingsOption(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) Color(0x334B7BE5) else Color(0x24141F2D),
        ),
        border = if (selected) BorderStroke(1.dp, Color(0xFF9ED6FF)) else null,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = description,
                color = Color(0xFFD3E3EE),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun DesktopAddSubscriptionLauncherCard(
    onClick: () -> Unit,
) {
    val borderColor = Color(0xFF9ED6FF)
    val cornerRadius = 20.dp
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .drawBehind {
                drawRoundRect(
                    color = borderColor,
                    topLeft = androidx.compose.ui.geometry.Offset(1.dp.toPx(), 1.dp.toPx()),
                    size = size.copy(
                        width = size.width - 2.dp.toPx(),
                        height = size.height - 2.dp.toPx(),
                    ),
                    cornerRadius = CornerRadius(cornerRadius.toPx(), cornerRadius.toPx()),
                    style = Stroke(
                        width = 1.5.dp.toPx(),
                        pathEffect = PathEffect.dashPathEffect(
                            floatArrayOf(12.dp.toPx(), 10.dp.toPx()),
                        ),
                    ),
                )
            },
        shape = RoundedCornerShape(cornerRadius),
        colors = CardDefaults.cardColors(containerColor = Color(0x141D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 22.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(Color(0x223C7AE6), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Filled.Add,
                    contentDescription = "Add new subscription",
                    tint = Color.White,
                )
            }
            Text(
                text = "Add new subscription",
                color = Color.White,
                fontSize = 16.sp,
            )
        }
    }
}

@Composable
private fun DesktopActionRow(
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onExportFile: () -> Unit,
    onExportClipboard: () -> Unit,
) {
    var showImportMenu by remember { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box {
            OutlinedButton(
                onClick = { showImportMenu = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text("Import")
            }
            DropdownMenu(
                expanded = showImportMenu,
                onDismissRequest = { showImportMenu = false },
            ) {
                DropdownMenuItem(
                    text = { Text("File") },
                    onClick = {
                        showImportMenu = false
                        onImportFile()
                    },
                )
                DropdownMenuItem(
                    text = { Text("Clipboard") },
                    onClick = {
                        showImportMenu = false
                        onImportClipboard()
                    },
                )
            }
        }
        Box {
            OutlinedButton(
                onClick = { showExportMenu = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text("Export")
            }
            DropdownMenu(
                expanded = showExportMenu,
                onDismissRequest = { showExportMenu = false },
            ) {
                DropdownMenuItem(
                    text = { Text("File") },
                    onClick = {
                        showExportMenu = false
                        onExportFile()
                    },
                )
                DropdownMenuItem(
                    text = { Text("Clipboard") },
                    onClick = {
                        showExportMenu = false
                        onExportClipboard()
                    },
                )
            }
        }
    }
}

private fun DesktopLocationRecord.toSharedRow(): SavedLocationRow {
    return SavedLocationRow(
        index = index,
        rawLink = rawLink,
        name = name,
        server = server,
        details = details,
        benchmarkDetail = benchmarkDetail,
        isValid = isValid,
        isSelected = isSelected,
    )
}
