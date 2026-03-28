package com.kardinal.vpncontrol.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import java.util.Locale

@Composable
fun VpnControlApp(
    state: MainUiState,
    onNavigateBack: () -> Unit,
    onToggleProfileDialog: () -> Unit,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onDnsEnabledChange: (Boolean) -> Unit,
    onDnsChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyChange: (SubscriptionRefreshPolicy) -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onSaveSubscriptionRefreshPolicy: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationGeneralUrlChange: (String) -> Unit,
    onValidationChatGptUrlChange: (String) -> Unit,
    onValidationCandidateCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onOpenMainTab: () -> Unit,
    onOpenLocationsTab: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onToggleSelectedLocationVpn: () -> Unit,
    onCloseLocationDialog: () -> Unit,
    onLocationDraftChange: (String) -> Unit,
    onSaveLocation: () -> Unit,
    onRoutingIgnoreRulesChange: (Boolean) -> Unit,
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
    val showBlockingProgress = state.isRefreshing || state.isStartingVpn

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(background),
    ) {
        HomeTabsScreen(
            state = state,
            onOpenMainTab = onOpenMainTab,
            onOpenLocationsTab = onOpenLocationsTab,
            onOpenRoutingRules = onOpenRoutingRules,
            onProfileChange = onProfileChange,
            onProfileSourceModeChange = onProfileSourceModeChange,
            onSaveProfile = onSaveProfile,
            onToggleDnsDialog = onToggleDnsDialog,
            onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
            onSubscriptionRefreshCustomHoursChange = onSubscriptionRefreshCustomHoursChange,
            onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
            onValidationGeneralUrlChange = onValidationGeneralUrlChange,
            onValidationChatGptUrlChange = onValidationChatGptUrlChange,
            onValidationCandidateCountChange = onValidationCandidateCountChange,
            onSaveValidationSettings = onSaveValidationSettings,
            onToggleVpn = onToggleVpn,
            onRefresh = onRefresh,
            onExportDiagnostics = onExportDiagnostics,
            onShowAddLocation = onShowAddLocation,
            onExportLocations = onExportLocations,
            onImportLocations = onImportLocations,
            onEditLocation = onEditLocation,
            onDeleteLocation = onDeleteLocation,
            onSelectLocation = onSelectLocation,
            onToggleSelectedLocationVpn = onToggleSelectedLocationVpn,
            onIgnoreRulesChange = onRoutingIgnoreRulesChange,
            onAppSearchChange = onRoutingAppSearchChange,
            onToggleProxyApp = onToggleProxyRoutingApp,
            onToggleDirectApp = onToggleDirectRoutingApp,
            onSelectAllProxyApps = onSelectAllProxyApps,
            onClearAllProxyApps = onClearAllProxyApps,
            onSelectAllDirectApps = onSelectAllDirectApps,
            onClearAllDirectApps = onClearAllDirectApps,
            onNationalDomainsChange = onRoutingNationalDomainsChange,
            onDirectDomainsChange = onRoutingDirectDomainsChange,
            onSaveRoutingRules = onSaveRoutingRules,
            onExportRoutingRules = onExportRoutingRules,
            onImportRoutingRules = onImportRoutingRules,
        )
    }

    if (showBlockingProgress) {
        BackHandler(enabled = true) {}
        RefreshProgressDialog(progressText = state.statusMessage)
    }

    BackHandler(
        enabled = !showBlockingProgress && (
            state.showProfileDialog ||
            state.showDnsDialog ||
            state.showRefreshPolicyDialog ||
            state.showValidationSettingsDialog ||
            state.showLocationDialog ||
            state.currentScreen != AppScreen.MAIN ||
            state.screenHistory.isNotEmpty()
        ),
    ) {
        when {
            state.showProfileDialog -> onToggleProfileDialog()
            state.showDnsDialog -> onToggleDnsDialog()
            state.showRefreshPolicyDialog -> onToggleRefreshPolicyDialog()
            state.showValidationSettingsDialog -> onToggleValidationSettingsDialog()
            state.showLocationDialog -> onCloseLocationDialog()
            else -> onNavigateBack()
        }
    }

    if (state.showProfileDialog) {
        AlertDialog(
            onDismissRequest = onToggleProfileDialog,
            title = { Text("Subscription URL") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        value = state.profileDraft,
                        onValueChange = onProfileChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                        label = { Text("Subscription URL") },
                    )
                    SourceModeOption(
                        title = "Use Subscription",
                        description = "Finding the best location downloads the subscription and updates saved locations.",
                        selected = state.profileSourceModeDraft == ProfileSourceMode.SUBSCRIPTION,
                        onClick = { onProfileSourceModeChange(ProfileSourceMode.SUBSCRIPTION) },
                    )
                    SourceModeOption(
                        title = "Use Saved Locations",
                        description = "Finding the best location tests the locations saved on the Locations tab.",
                        selected = state.profileSourceModeDraft == ProfileSourceMode.CURRENT_LOCATIONS,
                        onClick = { onProfileSourceModeChange(ProfileSourceMode.CURRENT_LOCATIONS) },
                    )
                }
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
                        Text("Use custom DNS")
                        Switch(
                            checked = state.useCustomDnsDraft,
                            onCheckedChange = onDnsEnabledChange,
                        )
                    }
                    OutlinedTextField(
                        value = state.customDnsDraft,
                        onValueChange = onDnsChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("DNS IP address") },
                        enabled = state.useCustomDnsDraft,
                        colors = routingTextFieldColors(),
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

    if (state.showRefreshPolicyDialog) {
        AlertDialog(
            onDismissRequest = onToggleRefreshPolicyDialog,
            title = { Text("Subscription Auto-Refresh", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Works only when Profile Source is set to Subscription. The app will periodically redownload the subscription and update the saved locations list.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                    listOf(
                        SubscriptionRefreshPolicy.OFF,
                        SubscriptionRefreshPolicy.EVERY_HOUR,
                        SubscriptionRefreshPolicy.CUSTOM,
                    ).forEach { policy ->
                        SourceModeOption(
                            title = policy.title,
                            description = when (policy) {
                                SubscriptionRefreshPolicy.OFF -> "Do not update the subscription in the background."
                                SubscriptionRefreshPolicy.EVERY_HOUR -> "Update saved locations from the subscription every hour."
                                SubscriptionRefreshPolicy.CUSTOM -> "Use a custom interval in hours."
                            },
                            selected = state.subscriptionRefreshPolicyDraft == policy,
                            onClick = { onSubscriptionRefreshPolicyChange(policy) },
                        )
                    }
                    if (state.subscriptionRefreshPolicyDraft == SubscriptionRefreshPolicy.CUSTOM) {
                        OutlinedTextField(
                            value = state.subscriptionRefreshCustomHoursDraft,
                            onValueChange = onSubscriptionRefreshCustomHoursChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Custom interval (hours)") },
                            placeholder = { Text("3") },
                            singleLine = true,
                            colors = routingTextFieldColors(),
                        )
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
        AlertDialog(
            onDismissRequest = onToggleValidationSettingsDialog,
            title = { Text("Location Test Settings", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        text = "The app uses these sites when testing locations. Concurrency matches the candidate count, up to 5.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                    OutlinedTextField(
                        value = state.validationGeneralUrlDraft,
                        onValueChange = onValidationGeneralUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Primary test site") },
                        placeholder = { Text("google.com or full URL") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationChatGptUrlDraft,
                        onValueChange = onValidationChatGptUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Secondary test site") },
                        placeholder = { Text("chatgpt.com or full URL") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationCandidateCountDraft,
                        onValueChange = onValidationCandidateCountChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Candidates to test") },
                        placeholder = { Text("3") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Current settings: ${state.validationSettings.displaySummary()}",
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

    if (state.showLocationDialog) {
        AlertDialog(
            onDismissRequest = onCloseLocationDialog,
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            title = {
                Text(
                    if (state.editingLocationIndex == null) "Add Location" else "Edit Location",
                    color = Color.White,
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.locationDraft,
                        onValueChange = onLocationDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 5,
                        label = { Text("Location config (VLESS link or JSON)") },
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Paste a vless:// link or a JSON config. The app validates it and saves it as a location.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveLocation) {
                    Text("Save", color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseLocationDialog) {
                    Text("Cancel", color = Color(0xFFD3E3EE))
                }
            },
        )
    }
}

@Composable
private fun RefreshProgressDialog(progressText: String) {
    Dialog(
        onDismissRequest = {},
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false,
            usePlatformDefaultWidth = false,
        ),
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0x8C08111F))
                .padding(horizontal = 28.dp),
            contentAlignment = Alignment.Center,
        ) {
            Card(
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF141F2D)),
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 28.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    CircularProgressIndicator(color = Color.White)
                    Text(
                        text = progressText.ifBlank { "Refreshing..." },
                        color = Color(0xFFD3E3EE),
                        fontSize = 16.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun HomeTabsScreen(
    state: MainUiState,
    onOpenMainTab: () -> Unit,
    onOpenLocationsTab: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationGeneralUrlChange: (String) -> Unit,
    onValidationChatGptUrlChange: (String) -> Unit,
    onValidationCandidateCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onToggleSelectedLocationVpn: () -> Unit,
    onIgnoreRulesChange: (Boolean) -> Unit,
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onToggleDirectApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
    onNationalDomainsChange: (String) -> Unit,
    onDirectDomainsChange: (String) -> Unit,
    onSaveRoutingRules: () -> Unit,
    onExportRoutingRules: () -> Unit,
    onImportRoutingRules: () -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(
                    if (state.currentScreen == AppScreen.ROUTING_RULES) {
                        Color(0xFF141F2D)
                    } else {
                        Color.Transparent
                    },
                ),
        ) {
            when (state.currentScreen) {
                AppScreen.MAIN -> MainScreen(
                    state = state,
                    onProfileChange = onProfileChange,
                    onProfileSourceModeChange = onProfileSourceModeChange,
                    onSaveProfile = onSaveProfile,
                    onToggleDnsDialog = onToggleDnsDialog,
                    onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
                    onSubscriptionRefreshCustomHoursChange = onSubscriptionRefreshCustomHoursChange,
                    onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
                    onValidationGeneralUrlChange = onValidationGeneralUrlChange,
                    onValidationChatGptUrlChange = onValidationChatGptUrlChange,
                    onValidationCandidateCountChange = onValidationCandidateCountChange,
                    onSaveValidationSettings = onSaveValidationSettings,
                    onToggleVpn = onToggleVpn,
                    onRefresh = onRefresh,
                    onExportDiagnostics = onExportDiagnostics,
                )
                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    onShowAddLocation = onShowAddLocation,
                    onExportLocations = onExportLocations,
                    onImportLocations = onImportLocations,
                    onEditLocation = onEditLocation,
                    onDeleteLocation = onDeleteLocation,
                    onSelectLocation = onSelectLocation,
                    onToggleSelectedLocationVpn = onToggleSelectedLocationVpn,
                )
                AppScreen.ROUTING_RULES -> RoutingRulesScreen(
                    state = state,
                    onIgnoreRulesChange = onIgnoreRulesChange,
                    onAppSearchChange = onAppSearchChange,
                    onToggleProxyApp = onToggleProxyApp,
                    onToggleDirectApp = onToggleDirectApp,
                    onSelectAllProxyApps = onSelectAllProxyApps,
                    onClearAllProxyApps = onClearAllProxyApps,
                    onSelectAllDirectApps = onSelectAllDirectApps,
                    onClearAllDirectApps = onClearAllDirectApps,
                    onNationalDomainsChange = onNationalDomainsChange,
                    onDirectDomainsChange = onDirectDomainsChange,
                    onSave = onSaveRoutingRules,
                    onExport = onExportRoutingRules,
                    onImport = onImportRoutingRules,
                )
                else -> Unit
            }
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(Color(0xCC141F2D))
                .navigationBarsPadding(),
        ) {
            TabRow(
                selectedTabIndex = when (state.currentScreen) {
                    AppScreen.MAIN -> 0
                    AppScreen.LOCATIONS -> 1
                    AppScreen.ROUTING_RULES -> 2
                },
                modifier = Modifier.fillMaxWidth(),
                containerColor = Color.Transparent,
                contentColor = Color.White,
                divider = {},
            ) {
                Tab(
                    selected = state.currentScreen == AppScreen.MAIN,
                    onClick = onOpenMainTab,
                    text = { Text("Main") },
                )
                Tab(
                    selected = state.currentScreen == AppScreen.LOCATIONS,
                    onClick = onOpenLocationsTab,
                    text = { Text("Locations") },
                )
                Tab(
                    selected = state.currentScreen == AppScreen.ROUTING_RULES,
                    onClick = onOpenRoutingRules,
                    text = { Text("Routing Rules") },
                )
            }
        }
    }
}

@Composable
private fun SourceModeOption(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) Color(0x143983FF) else Color(0x08141F2D),
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = onClick)
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, color = Color.White, fontWeight = FontWeight.SemiBold)
                Text(description, color = Color(0xFFD3E3EE), fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun MainScreen(
    state: MainUiState,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationGeneralUrlChange: (String) -> Unit,
    onValidationChatGptUrlChange: (String) -> Unit,
    onValidationCandidateCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
) {
    var advancedMenuExpanded by remember { mutableStateOf(false) }
    val activeMode = state.profileSourceModeDraft

    Scaffold(
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
                    Box {
                        IconButton(onClick = { advancedMenuExpanded = true }) {
                            Icon(
                                imageVector = Icons.Filled.MoreVert,
                                contentDescription = "Advanced settings",
                                tint = Color.White,
                            )
                        }
                        DropdownMenu(
                            expanded = advancedMenuExpanded,
                            onDismissRequest = { advancedMenuExpanded = false },
                        ) {
                            DropdownMenuItem(
                                text = { Text("Custom DNS") },
                                onClick = {
                                    advancedMenuExpanded = false
                                    onToggleDnsDialog()
                                },
                            )
                            DropdownMenuItem(
                                text = {
                                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Text("Subscription Auto-Refresh")
                                        Text(
                                            state.subscriptionRefreshPolicy.displayValue(
                                                state.subscriptionRefreshCustomHours,
                                            ),
                                            color = Color(0xFF4A6070),
                                            fontSize = 12.sp,
                                        )
                                    }
                                },
                                onClick = {
                                    advancedMenuExpanded = false
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
                                    advancedMenuExpanded = false
                                    onToggleValidationSettingsDialog()
                                },
                            )
                        }
                    }
                }
                Text(
                    text = if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                        "Subscription is active. Finding the best location updates saved locations from the subscription and selects the best one."
                    } else {
                        "Saved locations are active. Finding the best location tests the locations saved on the Locations tab."
                    },
                    color = Color(0xFFD3E3EE),
                )

                StatusCard(state)

                ActionButton(
                    label = if (state.isVpnRunning) "Stop VPN" else "Start VPN",
                    sublabel = if (state.hasVpnPermission) "Connect or disconnect the VPN" else "VPN permission required",
                    onClick = onToggleVpn,
                    enabled = !state.isBusy,
                )
                ActionButton(
                    label = "Find the best location",
                    sublabel = state.lastBenchmarkSummary.ifBlank {
                        if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                            "Find the best location from the subscription"
                        } else {
                            "Find the best location from saved locations"
                        }
                    },
                    onClick = onRefresh,
                    enabled = !state.isBusy,
                )
                ProfileSourceCard(
                    state = state,
                    onProfileChange = onProfileChange,
                    onProfileSourceModeChange = onProfileSourceModeChange,
                    onSaveProfile = onSaveProfile,
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
private fun LocationsScreen(
    state: MainUiState,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onToggleSelectedLocationVpn: () -> Unit,
) {
    val selectedLocation = selectedLocationReference(state)
    val locations = state.currentLocations
        .mapIndexed { index, rawLink ->
            val parsed = runCatching { LocationConfigs.decodeStoredLocation(rawLink) }.getOrNull()
            SavedLocationRow(
                index = index,
                rawLink = rawLink,
                name = parsed?.remarks ?: "Invalid location config",
                server = parsed?.server ?: "Could not read this location",
                details = parsed?.let {
                    listOf(it.serverPort.toString(), it.network, it.sni)
                        .filter { value -> value.isNotBlank() }
                        .joinToString(" • ")
                } ?: "Tap edit to fix this location",
                benchmarkDetail = stripBenchmarkLocationPrefix(
                    state.locationBenchmarkDetails[rawLink].orEmpty(),
                ),
                isValid = parsed != null,
                isSelected = rawLink == selectedLocation,
            )
        }
        .sortedWith(locationRowComparator())
    val selectedName = locations.firstOrNull { it.isSelected }?.name ?: state.selectedProfileName.takeIf { it.isNotBlank() }

    Scaffold(
        containerColor = Color.Transparent,
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
                    Text("Locations", color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.Bold)
                    Text(
                        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                            "Location search uses the subscription. This list is updated from it each time."
                        } else {
                            "Location search uses the saved locations below. No subscription is required."
                        },
                        color = Color(0xFFD3E3EE),
                    )
                    Text(
                        "Saved locations: ${locations.size}",
                        color = Color(0xFF9ED6FF),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = if (selectedName.isNullOrBlank()) {
                            "Selected: none"
                        } else {
                            "Selected: $selectedName"
                        },
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Button(
                    onClick = onShowAddLocation,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                ) {
                    Text("Add Location")
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(
                    onClick = onImportLocations,
                    enabled = !state.isBusy,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text("Import Locations")
                }
                OutlinedButton(
                    onClick = onExportLocations,
                    enabled = !state.isBusy,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text("Export Locations")
                }
            }

            Card(
                modifier = Modifier.fillMaxSize(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
            ) {
                if (locations.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(20.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                "No locations cached yet. Find the best location in subscription mode to load them, or add your own."
                            } else {
                                "No saved locations yet. Add one manually or switch back to subscription mode."
                            },
                            color = Color(0xFFD3E3EE),
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(locations, key = { "${it.index}:${it.rawLink}" }) { location ->
                            LocationRowCard(
                                location = location,
                                isVpnRunning = state.isVpnRunning,
                                enabled = !state.isBusy,
                                onPrimaryAction = {
                                    if (location.isSelected) {
                                        onToggleSelectedLocationVpn()
                                    } else {
                                        onSelectLocation(location.index)
                                    }
                                },
                                onEdit = { onEditLocation(location.index) },
                                onDelete = { onDeleteLocation(location.index) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProfileSourceCard(
    state: MainUiState,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
) {
    val activeMode = state.profileSourceModeDraft
    val useSubscription = activeMode == ProfileSourceMode.SUBSCRIPTION

    Card(
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Profile Source", color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text(
                text = if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                    "Subscription is active. Finding the best location downloads the subscription and updates saved locations."
                } else {
                    "Saved locations are active. Finding the best location tests the locations saved on the Locations tab."
                },
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
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
                        modifier = Modifier.weight(1f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            text = if (useSubscription) "Subscription" else "Saved Locations",
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = if (useSubscription) {
                                "Turn off to use the locations saved on the Locations tab."
                            } else {
                                "Turn on to use the subscription URL."
                            },
                            color = Color(0xFFD3E3EE),
                            fontSize = 12.sp,
                        )
                    }
                    Switch(
                        checked = useSubscription,
                        onCheckedChange = { checked ->
                            onProfileSourceModeChange(
                                if (checked) ProfileSourceMode.SUBSCRIPTION else ProfileSourceMode.CURRENT_LOCATIONS,
                            )
                            onSaveProfile()
                        },
                    )
                }
            }
            if (useSubscription) {
                OutlinedTextField(
                    value = state.profileDraft,
                    onValueChange = onProfileChange,
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                    label = { Text("Subscription URL") },
                    colors = routingTextFieldColors(),
                )
                Button(
                    onClick = onSaveProfile,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    colors = darkButtonColors(),
                ) {
                    Text("Save Subscription")
                }
            }
        }
    }
}

@Composable
private fun RoutingRulesScreen(
    state: MainUiState,
    onIgnoreRulesChange: (Boolean) -> Unit,
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
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 20.dp, top = 18.dp, end = 20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 0.dp),
        ) {
            item {
                Button(
                    onClick = onSave,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = darkButtonColors(),
                ) {
                    Text("Save Rules")
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
                        border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                        colors = darkOutlinedButtonColors(),
                    ) {
                        Text("Import Rules")
                    }
                    OutlinedButton(
                        onClick = onExport,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                        shape = RoundedCornerShape(16.dp),
                        border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                        colors = darkOutlinedButtonColors(),
                    ) {
                        Text("Export Rules")
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
                        text = "Choose which apps use the VPN and which domains bypass it. You can also ignore all saved rules temporarily.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 14.sp,
                    )
                }
            }
            item {
                CompactSummaryCard(state)
            }
            item {
                IgnoreRulesCard(
                    enabled = state.routingIgnoreRulesDraft,
                    onEnabledChange = onIgnoreRulesChange,
                )
            }
            item {
                AppSelectionSectionCard(
                    title = "Proxy Apps",
                    count = state.routingProxyPackagesDraft.size,
                    description = "Only these apps use the VPN. Domain bypass rules still apply.",
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
                    title = "Country-code Domains",
                    description = "One per line. Traffic to these domains goes directly, without VPN. Example: ru",
                    value = state.routingNationalDomainsDraft,
                    onValueChange = onNationalDomainsChange,
                )
            }
            item {
                RuleTextField(
                    title = "Bypass Domains",
                    description = "One per line. Traffic to these domains goes directly, without VPN. Example: magnit.com",
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
                            text = "Tap Proxy or Direct on an app row. Proxy apps are listed first, then direct apps, then unassigned apps.",
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
                if (state.routingIgnoreRulesDraft) {
                    "Ignore rules is on. App/domain rules are saved but not applied."
                } else {
                    "Ignore rules is off. Saved app/domain rules are active."
                },
                color = if (state.routingIgnoreRulesDraft) Color(0xFFFFE0A3) else Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                "${state.routingNationalDomainsDraft.countEntries()} country-code domains • " +
                    "${state.routingDirectDomainsDraft.countEntries()} bypass domains",
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
private fun IgnoreRulesCard(
    enabled: Boolean,
    onEnabledChange: (Boolean) -> Unit,
) {
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
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text("Ignore Rules", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(
                    if (enabled) {
                        "User-defined app and domain rules are ignored. Normal app traffic goes through the VPN."
                    } else {
                        "User-defined app and domain rules are applied."
                    },
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onEnabledChange,
            )
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
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
                ) {
                    Text("Select All")
                }
                OutlinedButton(
                    onClick = onClearAll,
                    enabled = enableClearAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
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
                        colors = darkOutlinedButtonColors(),
                    ) {
                        Text(
                            text = if (isProxy) "Proxy On" else "Proxy",
                            color = if (isProxy) Color(0xFF83B7FF) else Color.White,
                            fontSize = 11.sp,
                        )
                    }
                    OutlinedButton(
                        onClick = onToggleDirect,
                        shape = RoundedCornerShape(12.dp),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 2.dp),
                        colors = darkOutlinedButtonColors(),
                    ) {
                        Text(
                            text = if (isDirect) "Direct On" else "Direct",
                            color = if (isDirect) Color(0xFF7FE7B5) else Color.White,
                            fontSize = 11.sp,
                        )
                    }
                }
                if (app.isSystemApp) {
                    Text(
                        text = "System",
                        color = Color(0xFF9ED6FF),
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun LocationRowCard(
    location: SavedLocationRow,
    isVpnRunning: Boolean,
    enabled: Boolean,
    onPrimaryAction: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    val isSelectedAndRunning = location.isSelected && isVpnRunning
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                !location.isValid -> Color(0x33A44A4A)
                location.isSelected -> Color(0x334B7BE5)
                else -> Color(0x1F203041)
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = location.name,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = location.server,
                    color = Color(0xFFD3E3EE),
                    fontSize = 13.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = location.details,
                    color = if (location.isValid) Color(0xFF9ED6FF) else Color(0xFFFFC4C4),
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (location.benchmarkDetail.isNotBlank()) {
                    Text(
                        text = location.benchmarkDetail,
                        color = Color(0xFFD3E3EE),
                        fontSize = 11.sp,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (location.isSelected) {
                    Text(
                        text = if (isVpnRunning) "In use" else "Selected",
                        color = Color(0xFFFFE0A3),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.Start),
            ) {
                OutlinedButton(
                    onClick = onPrimaryAction,
                    enabled = enabled && location.isValid,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = if (location.isSelected) Color(0xFFFFE0A3) else Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = when {
                            isSelectedAndRunning -> Icons.Filled.Stop
                            else -> Icons.Filled.PlayArrow
                        },
                        contentDescription = when {
                            isSelectedAndRunning -> "Stop VPN for this location"
                            location.isSelected -> "Start VPN for this location"
                            else -> "Select this location"
                        },
                    )
                }
                OutlinedButton(
                    onClick = onEdit,
                    enabled = enabled,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Edit,
                        contentDescription = "Edit location",
                    )
                }
                OutlinedButton(
                    onClick = onDelete,
                    enabled = enabled,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color(0xFFFFC4C4),
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = "Delete location",
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
    if (state.routingRules.ignoreRules) {
        return "Ignored • all normal app traffic through VPN"
    }
    return buildString {
        append("${state.routingRules.proxyPackages.size} proxy")
        append(" • ")
        append("${state.routingRules.bypassPackages.size} direct")
        append(" • ")
        append("${state.routingRules.nationalDomainSuffixes.size} country-code domains")
        append(" • ")
        append("${state.routingRules.directDomainSuffixes.size} bypass domains")
    }
}

private fun profileSourceSummary(state: MainUiState): String {
    return when (state.profileSourceMode) {
        ProfileSourceMode.SUBSCRIPTION -> {
            val suffix = state.profileUrl.ifBlank { "No URL set" }
            "Use subscription • $suffix"
        }
        ProfileSourceMode.CURRENT_LOCATIONS -> {
            "Use saved locations • ${state.currentLocations.size} saved"
        }
    }
}

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        packageName in state.routingBypassPackagesDraft -> 1
        else -> 2
    }
}

private fun selectedLocationReference(state: MainUiState): String {
    return state.selectedProfileJson.ifBlank {
        state.selectedProfileRawLink
            .takeIf { it.isNotBlank() }
            ?.let { raw ->
                runCatching {
                    LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(raw))
                }.getOrDefault(raw)
            }
            .orEmpty()
    }
}

private fun locationRowComparator(): Comparator<SavedLocationRow> {
    return compareBy<SavedLocationRow> { locationBenchmarkRank(it.benchmarkDetail) }
        .thenBy { parseBenchmarkScore(it.benchmarkDetail) ?: Double.POSITIVE_INFINITY }
        .thenBy { parseBenchmarkTimingMillis(it.benchmarkDetail) ?: Double.POSITIVE_INFINITY }
        .thenBy { it.name.lowercase(Locale.ROOT) }
}

private fun locationBenchmarkRank(detail: String): Int {
    return when {
        parseBenchmarkScore(detail) != null -> 0
        parseBenchmarkTimingMillis(detail) != null -> 1
        else -> 2
    }
}

private fun parseBenchmarkScore(detail: String): Double? {
    return Regex("""\bscore=([0-9]+(?:\.[0-9]+)?)""")
        .find(detail)
        ?.groupValues
        ?.getOrNull(1)
        ?.toDoubleOrNull()
}

private fun parseBenchmarkTimingMillis(detail: String): Double? {
    return Regex("""\btcp=([0-9]+(?:\.[0-9]+)?)ms""")
        .find(detail)
        ?.groupValues
        ?.getOrNull(1)
        ?.toDoubleOrNull()
}

private fun stripBenchmarkLocationPrefix(detail: String): String {
    return detail.substringAfter(": ", detail).trim()
}

@Composable
private fun darkButtonColors() = ButtonDefaults.buttonColors(
    containerColor = Color(0xFF2E6D9C),
    contentColor = Color.White,
    disabledContainerColor = Color(0xFF324B5E),
    disabledContentColor = Color(0xFF9FB8C8),
)

@Composable
private fun darkOutlinedButtonColors() = ButtonDefaults.outlinedButtonColors(
    contentColor = Color.White,
    disabledContentColor = Color(0xFF9FB8C8),
)

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

private data class SavedLocationRow(
    val index: Int,
    val rawLink: String,
    val name: String,
    val server: String,
    val details: String,
    val benchmarkDetail: String,
    val isValid: Boolean,
    val isSelected: Boolean,
)
