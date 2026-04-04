package com.kardinal.vpncontrol.ui

import android.content.Intent
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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Tune
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
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.RemoteSourcePreview
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.data.SingBoxConfigFactory
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import kotlinx.coroutines.delay

@Composable
fun VpnControlApp(
    state: MainUiState,
    onNavigateBack: () -> Unit,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshActiveSubscription: () -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
    onCloseProfileHistoryRenameDialog: () -> Unit,
    onProfileHistoryRenameDraftChange: (String) -> Unit,
    onSaveProfileHistoryRename: () -> Unit,
    onCloseLocationMutationBlockedDialog: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onDnsEnabledChange: (Boolean) -> Unit,
    onDnsChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleUiSettingsDialog: () -> Unit,
    onSessionStatsEnabledChange: (Boolean) -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyChange: (SubscriptionRefreshPolicy) -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onSaveSubscriptionRefreshPolicy: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationPrimaryUrlChange: (String) -> Unit,
    onValidationSecondaryUrlChange: (String) -> Unit,
    onValidationBatchSizeChange: (String) -> Unit,
    onValidationRetryCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onAppModeChange: (AppMode) -> Unit,
    onOpenMainTab: () -> Unit,
    onOpenProfileTab: () -> Unit,
    onOpenLocationsTab: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onBenchmarkLocation: (Int) -> Unit,
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
    onShowAddRuleSetDialog: () -> Unit,
    onEditRuleSet: (String) -> Unit,
    onDeleteRuleSet: (String) -> Unit,
    onCloseRuleSetDialog: () -> Unit,
    onRuleSetNameChange: (String) -> Unit,
    onRuleSetSourceChange: (String) -> Unit,
    onRuleSetSourceTypeChange: (RoutingRuleSetSourceType) -> Unit,
    onRuleSetFormatChange: (RoutingRuleSetFormat) -> Unit,
    onRuleSetActionChange: (RoutingRuleSetAction) -> Unit,
    onRuleSetUpdateHoursChange: (String) -> Unit,
    onSaveRuleSet: () -> Unit,
    onSaveRoutingRules: () -> Unit,
    onExportRoutingRules: () -> Unit,
    onImportRoutingRules: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onCancelBusyAction: () -> Unit,
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
            onOpenProfileTab = onOpenProfileTab,
            onOpenLocationsTab = onOpenLocationsTab,
            onOpenRoutingRules = onOpenRoutingRules,
            onProfileChange = onProfileChange,
            onProfileSourceModeChange = onProfileSourceModeChange,
            onSaveProfile = onSaveProfile,
            onClearProfileSource = onClearProfileSource,
            onToggleAddSubscriptionEditor = onToggleAddSubscriptionEditor,
            onRefreshActiveSubscription = onRefreshActiveSubscription,
            onRefreshAllSubscriptions = onRefreshAllSubscriptions,
            onUseProfileHistoryEntry = onUseProfileHistoryEntry,
            onShowProfileHistoryRenameDialog = onShowProfileHistoryRenameDialog,
            onDeleteProfileHistoryEntry = onDeleteProfileHistoryEntry,
            onToggleDnsDialog = onToggleDnsDialog,
            onToggleUiSettingsDialog = onToggleUiSettingsDialog,
            onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
            onSubscriptionRefreshCustomHoursChange = onSubscriptionRefreshCustomHoursChange,
            onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
            onValidationPrimaryUrlChange = onValidationPrimaryUrlChange,
            onValidationSecondaryUrlChange = onValidationSecondaryUrlChange,
            onValidationBatchSizeChange = onValidationBatchSizeChange,
            onValidationRetryCountChange = onValidationRetryCountChange,
            onSaveValidationSettings = onSaveValidationSettings,
            onToggleAppModeDialog = onToggleAppModeDialog,
            onAppModeChange = onAppModeChange,
            onToggleVpn = onToggleVpn,
            onRefresh = onRefresh,
            onExportDiagnostics = onExportDiagnostics,
            onShowAddLocation = onShowAddLocation,
            onExportLocations = onExportLocations,
            onImportLocations = onImportLocations,
            onEditLocation = onEditLocation,
            onDeleteLocation = onDeleteLocation,
            onBenchmarkLocation = onBenchmarkLocation,
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
            onShowAddRuleSetDialog = onShowAddRuleSetDialog,
            onEditRuleSet = onEditRuleSet,
            onDeleteRuleSet = onDeleteRuleSet,
            onCloseRuleSetDialog = onCloseRuleSetDialog,
            onRuleSetNameChange = onRuleSetNameChange,
            onRuleSetSourceChange = onRuleSetSourceChange,
            onRuleSetSourceTypeChange = onRuleSetSourceTypeChange,
            onRuleSetFormatChange = onRuleSetFormatChange,
            onRuleSetActionChange = onRuleSetActionChange,
            onRuleSetUpdateHoursChange = onRuleSetUpdateHoursChange,
            onSaveRuleSet = onSaveRuleSet,
            onSaveRoutingRules = onSaveRoutingRules,
            onExportRoutingRules = onExportRoutingRules,
            onImportRoutingRules = onImportRoutingRules,
        )
    }

    if (showBlockingProgress) {
        BackHandler(enabled = true) {}
        RefreshProgressDialog(
            progressText = state.statusMessage,
            onCancel = onCancelBusyAction,
        )
    }

    BackHandler(
        enabled = !showBlockingProgress && (
            state.showProfileHistoryRenameDialog ||
            state.showLocationMutationBlockedDialog ||
            state.showDnsDialog ||
            state.showUiSettingsDialog ||
            state.showAppModeDialog ||
            state.showRefreshPolicyDialog ||
            state.showValidationSettingsDialog ||
            state.showLocationDialog ||
            state.currentScreen != AppScreen.MAIN ||
            state.screenHistory.isNotEmpty()
        ),
    ) {
        when {
            state.showProfileHistoryRenameDialog -> onCloseProfileHistoryRenameDialog()
            state.showLocationMutationBlockedDialog -> onCloseLocationMutationBlockedDialog()
            state.showDnsDialog -> onToggleDnsDialog()
            state.showUiSettingsDialog -> onToggleUiSettingsDialog()
            state.showAppModeDialog -> onToggleAppModeDialog()
            state.showRefreshPolicyDialog -> onToggleRefreshPolicyDialog()
            state.showValidationSettingsDialog -> onToggleValidationSettingsDialog()
            state.showLocationDialog -> onCloseLocationDialog()
            else -> onNavigateBack()
        }
    }

    if (state.showProfileHistoryRenameDialog) {
        AlertDialog(
            onDismissRequest = onCloseProfileHistoryRenameDialog,
            title = { Text("Subscription Name", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.profileHistoryRenameDraft,
                        onValueChange = onProfileHistoryRenameDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Name") },
                        placeholder = { Text("My subscription") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Leave it empty to use the detected name again.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveProfileHistoryRename) {
                    Text("Save", color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseProfileHistoryRenameDialog) {
                    Text("Cancel", color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showLocationMutationBlockedDialog) {
        AlertDialog(
            onDismissRequest = onCloseLocationMutationBlockedDialog,
            title = { Text("Read-only location", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Text(
                    text = state.locationMutationBlockedMessage,
                    color = Color(0xFFD3E3EE),
                )
            },
            confirmButton = {
                TextButton(onClick = onCloseLocationMutationBlockedDialog) {
                    Text("OK", color = Color(0xFF9ED6FF))
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

    if (state.showUiSettingsDialog) {
        AlertDialog(
            onDismissRequest = onToggleUiSettingsDialog,
            title = { Text("UI Settings", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
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
                                    text = "Session stats",
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = "Show or hide the Session card on the Main tab.",
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            Switch(
                                checked = state.sessionStatsEnabled,
                                onCheckedChange = onSessionStatsEnabledChange,
                            )
                        }
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = onToggleUiSettingsDialog) {
                    Text("Close", color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showAppModeDialog) {
        AlertDialog(
            onDismissRequest = onToggleAppModeDialog,
            title = { Text("Proxy Mode Settings", color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Default mode is VPN. Turn on Proxy Only to run a local HTTP/SOCKS mixed proxy instead of Android VPN.",
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
                                    text = if (state.appMode == AppMode.PROXY_ONLY) "Proxy Only" else "VPN",
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.appMode == AppMode.PROXY_ONLY) {
                                        "Local mixed proxy mode is enabled. Turn it off to use Android VPN mode."
                                    } else {
                                        "Android VPN mode is enabled. Turn on Proxy Only to expose a local mixed proxy instead."
                                    },
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            Switch(
                                checked = state.appMode == AppMode.PROXY_ONLY,
                                onCheckedChange = { enabled ->
                                    onAppModeChange(
                                        if (enabled) AppMode.PROXY_ONLY else AppMode.VPN,
                                    )
                                },
                            )
                        }
                    }
                    if (state.appMode == AppMode.PROXY_ONLY) {
                        ProxyOnlyInfoCard(state)
                    } else {
                        Text(
                            text = "VPN mode routes traffic through Android VpnService.",
                            color = Color(0xFF9FB8C8),
                            fontSize = 12.sp,
                        )
                    }
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
                        text = "The app uses these sites when testing locations. In subscription mode it checks the fastest locations in batches: top N first, then the next N, until the secondary site works.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                    OutlinedTextField(
                        value = state.validationPrimaryUrlDraft,
                        onValueChange = onValidationPrimaryUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Primary test site") },
                        placeholder = { Text("google.com or full URL") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationSecondaryUrlDraft,
                        onValueChange = onValidationSecondaryUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Secondary test site") },
                        placeholder = { Text("secondary-site.com or full URL") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationBatchSizeDraft,
                        onValueChange = onValidationBatchSizeChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Batch size") },
                        placeholder = { Text("3") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationRetryCountDraft,
                        onValueChange = onValidationRetryCountChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Retry count") },
                        placeholder = { Text("1") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Concurrency matches the current batch size, up to 5. Retry count reruns the whole search if no usable location is found. Current settings: ${state.validationSettings.displaySummary()}",
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

    if (state.showRuleSetDialog) {
        RuleSetEditorDialog(
            state = state,
            onDismiss = onCloseRuleSetDialog,
            onNameChange = onRuleSetNameChange,
            onSourceChange = onRuleSetSourceChange,
            onSourceTypeChange = onRuleSetSourceTypeChange,
            onFormatChange = onRuleSetFormatChange,
            onActionChange = onRuleSetActionChange,
            onUpdateHoursChange = onRuleSetUpdateHoursChange,
            onSave = onSaveRuleSet,
        )
    }

    if (state.showLocationDialog) {
        val clipboard = LocalClipboardManager.current
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
                    OutlinedButton(
                        onClick = {
                            clipboard.getText()?.text
                                ?.takeIf { it.isNotBlank() }
                                ?.let { onLocationDraftChange(it) }
                        },
                        shape = RoundedCornerShape(14.dp),
                        border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                        colors = darkOutlinedButtonColors(),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.ContentPaste,
                            contentDescription = "Paste location config",
                            modifier = Modifier.size(18.dp),
                        )
                        Spacer(modifier = Modifier.size(8.dp))
                        Text("Paste From Clipboard")
                    }
                    OutlinedTextField(
                        value = state.locationDraft,
                        onValueChange = onLocationDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 5,
                        label = { Text("Location config (proxy link or JSON)") },
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Paste a vless://, trojan://, ss://, or vmess:// link, a stored location JSON object, or a full sing-box JSON config. Remote source links belong in Profile Source on the Profile tab.",
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
private fun RefreshProgressDialog(
    progressText: String,
    onCancel: () -> Unit,
) {
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
                    OutlinedButton(
                        onClick = onCancel,
                        shape = RoundedCornerShape(18.dp),
                        border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White,
                        ),
                    ) {
                        Text("Cancel")
                    }
                }
            }
        }
    }

}

@Composable
private fun HomeTabsScreen(
    state: MainUiState,
    onOpenMainTab: () -> Unit,
    onOpenProfileTab: () -> Unit,
    onOpenLocationsTab: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshActiveSubscription: () -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
    onToggleDnsDialog: () -> Unit,
    onToggleUiSettingsDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationPrimaryUrlChange: (String) -> Unit,
    onValidationSecondaryUrlChange: (String) -> Unit,
    onValidationBatchSizeChange: (String) -> Unit,
    onValidationRetryCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onAppModeChange: (AppMode) -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onBenchmarkLocation: (Int) -> Unit,
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
    onShowAddRuleSetDialog: () -> Unit,
    onEditRuleSet: (String) -> Unit,
    onDeleteRuleSet: (String) -> Unit,
    onCloseRuleSetDialog: () -> Unit,
    onRuleSetNameChange: (String) -> Unit,
    onRuleSetSourceChange: (String) -> Unit,
    onRuleSetSourceTypeChange: (RoutingRuleSetSourceType) -> Unit,
    onRuleSetFormatChange: (RoutingRuleSetFormat) -> Unit,
    onRuleSetActionChange: (RoutingRuleSetAction) -> Unit,
    onRuleSetUpdateHoursChange: (String) -> Unit,
    onSaveRuleSet: () -> Unit,
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
                    onToggleDnsDialog = onToggleDnsDialog,
                    onToggleUiSettingsDialog = onToggleUiSettingsDialog,
                    onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
                    onSubscriptionRefreshCustomHoursChange = onSubscriptionRefreshCustomHoursChange,
                    onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
                    onValidationPrimaryUrlChange = onValidationPrimaryUrlChange,
                    onValidationSecondaryUrlChange = onValidationSecondaryUrlChange,
                    onValidationBatchSizeChange = onValidationBatchSizeChange,
                    onValidationRetryCountChange = onValidationRetryCountChange,
                    onSaveValidationSettings = onSaveValidationSettings,
                    onToggleAppModeDialog = onToggleAppModeDialog,
                    onToggleVpn = onToggleVpn,
                    onRefresh = onRefresh,
                    onExportDiagnostics = onExportDiagnostics,
                )
                AppScreen.PROFILE -> ProfileScreen(
                    state = state,
                    onProfileChange = onProfileChange,
                    onProfileSourceModeChange = onProfileSourceModeChange,
                    onSaveProfile = onSaveProfile,
                    onClearProfileSource = onClearProfileSource,
                    onToggleAddSubscriptionEditor = onToggleAddSubscriptionEditor,
                    onRefreshActiveSubscription = onRefreshActiveSubscription,
                    onRefreshAllSubscriptions = onRefreshAllSubscriptions,
                    onUseProfileHistoryEntry = onUseProfileHistoryEntry,
                    onShowProfileHistoryRenameDialog = onShowProfileHistoryRenameDialog,
                    onDeleteProfileHistoryEntry = onDeleteProfileHistoryEntry,
                )
                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    onShowAddLocation = onShowAddLocation,
                    onExportLocations = onExportLocations,
                    onImportLocations = onImportLocations,
                    onEditLocation = onEditLocation,
                    onDeleteLocation = onDeleteLocation,
                    onBenchmarkLocation = onBenchmarkLocation,
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
                    onShowAddRuleSetDialog = onShowAddRuleSetDialog,
                    onEditRuleSet = onEditRuleSet,
                    onDeleteRuleSet = onDeleteRuleSet,
                    onCloseRuleSetDialog = onCloseRuleSetDialog,
                    onRuleSetNameChange = onRuleSetNameChange,
                    onRuleSetSourceChange = onRuleSetSourceChange,
                    onRuleSetSourceTypeChange = onRuleSetSourceTypeChange,
                    onRuleSetFormatChange = onRuleSetFormatChange,
                    onRuleSetActionChange = onRuleSetActionChange,
                    onRuleSetUpdateHoursChange = onRuleSetUpdateHoursChange,
                    onSaveRuleSet = onSaveRuleSet,
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
                    AppScreen.PROFILE -> 1
                    AppScreen.LOCATIONS -> 2
                    AppScreen.ROUTING_RULES -> 3
                },
                modifier = Modifier.fillMaxWidth(),
                containerColor = Color.Transparent,
                contentColor = Color.White,
                divider = {},
            ) {
                Tab(
                    selected = state.currentScreen == AppScreen.MAIN,
                    onClick = onOpenMainTab,
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Home,
                            contentDescription = "Main",
                        )
                    },
                )
                Tab(
                    selected = state.currentScreen == AppScreen.PROFILE,
                    onClick = onOpenProfileTab,
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Person,
                            contentDescription = "Profile",
                        )
                    },
                )
                Tab(
                    selected = state.currentScreen == AppScreen.LOCATIONS,
                    onClick = onOpenLocationsTab,
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Public,
                            contentDescription = "Locations",
                        )
                    },
                )
                Tab(
                    selected = state.currentScreen == AppScreen.ROUTING_RULES,
                    onClick = onOpenRoutingRules,
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.Tune,
                            contentDescription = "Rules",
                        )
                    },
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
    onToggleDnsDialog: () -> Unit,
    onToggleUiSettingsDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationPrimaryUrlChange: (String) -> Unit,
    onValidationSecondaryUrlChange: (String) -> Unit,
    onValidationBatchSizeChange: (String) -> Unit,
    onValidationRetryCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onToggleVpn: () -> Unit,
    onRefresh: () -> Unit,
    onExportDiagnostics: () -> Unit,
) {
    var advancedMenuExpanded by remember { mutableStateOf(false) }
    val activeMode = state.profileSourceMode
    val selectedLocationOutsideActiveSubscription =
        activeMode == ProfileSourceMode.SUBSCRIPTION &&
            state.selectedProfileName.isNotBlank() &&
            state.selectedProfileSourceUrl != state.profileUrl

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
                                        Text("UI Settings")
                                        Text(
                                            if (state.sessionStatsEnabled) "Session stats on" else "Session stats off",
                                            color = Color(0xFF4A6070),
                                            fontSize = 12.sp,
                                        )
                                    }
                                },
                                onClick = {
                                    advancedMenuExpanded = false
                                    onToggleUiSettingsDialog()
                                },
                            )
                            DropdownMenuItem(
                                text = {
                                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                        Text("Proxy Mode Settings")
                                        Text(
                                            if (state.appMode == AppMode.VPN) "VPN mode" else "Proxy-only mode",
                                            color = Color(0xFF4A6070),
                                            fontSize = 12.sp,
                                        )
                                    }
                                },
                                onClick = {
                                    advancedMenuExpanded = false
                                    onToggleAppModeDialog()
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
                        "Subscription mode is active. Finding the best location downloads locations from the remote source and updates the saved list."
                    } else {
                        "Saved locations are active. Finding the best location tests the locations saved on the Locations tab."
                    },
                    color = Color(0xFFD3E3EE),
                )
                if (selectedLocationOutsideActiveSubscription) {
                    SubscriptionMismatchWarningCard(state)
                }

                StatusCard(state)
                if (state.sessionStatsEnabled) {
                    SessionCard(state)
                }

                ActionButton(
                    icon = Icons.Filled.PowerSettingsNew,
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
                ActionButton(
                    icon = Icons.Filled.MyLocation,
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

@Composable
private fun ProxyOnlyInfoCard(state: MainUiState) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val proxyAddress = "127.0.0.1:${SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT}"
    val shareText = buildString {
        appendLine("VPN Control local proxy")
        appendLine("Mode: mixed HTTP/SOCKS")
        appendLine("Address: $proxyAddress")
    }

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
            Text("Local Proxy", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(
                text = "Use this local mixed proxy in apps that support HTTP or SOCKS proxies.",
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                text = proxyAddress,
                color = Color(0xFF9ED6FF),
                fontSize = 18.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = if (state.isVpnRunning) {
                    "Status: proxy is running on this address"
                } else {
                    "Status: proxy is stopped"
                },
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(proxyAddress))
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text("Copy Address")
                }
                OutlinedButton(
                    onClick = {
                        context.startActivity(
                            Intent.createChooser(
                                Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_SUBJECT, "VPN Control local proxy")
                                    putExtra(Intent.EXTRA_TEXT, shareText)
                                },
                                "Share proxy address",
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text("Share")
                }
            }
        }
    }
}

@Composable
private fun ProfileScreen(
    state: MainUiState,
    onProfileChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshActiveSubscription: () -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
) {
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
                        Text("Profile", color = Color.White, fontSize = 30.sp, fontWeight = FontWeight.Bold)
                        Text(
                            "Choose where the app gets locations from. Use a remote source in subscription mode, or work only with the saved list from the Locations tab.",
                            color = Color(0xFFD3E3EE),
                        )
                        Text(
                            "Selected profile: ${activeProfileLabel(state)}",
                            color = Color(0xFF9ED6FF),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
                ProfileSourceCard(
                    state = state,
                    onProfileChange = onProfileChange,
                    onProfileSourceModeChange = onProfileSourceModeChange,
                    onSaveProfile = onSaveProfile,
                    onClearProfileSource = onClearProfileSource,
                    onToggleAddSubscriptionEditor = onToggleAddSubscriptionEditor,
                    onRefreshActiveSubscription = onRefreshActiveSubscription,
                    onRefreshAllSubscriptions = onRefreshAllSubscriptions,
                    onUseProfileHistoryEntry = onUseProfileHistoryEntry,
                    onShowProfileHistoryRenameDialog = onShowProfileHistoryRenameDialog,
                    onDeleteProfileHistoryEntry = onDeleteProfileHistoryEntry,
                )
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
    onBenchmarkLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onToggleSelectedLocationVpn: () -> Unit,
) {
    val selectedLocation = LocationConfigs.selectedStoredReference(
        selectedProfileJson = state.selectedProfileJson,
        selectedProfileRawLink = state.selectedProfileRawLink,
    )
    val selectedLocationOutsideActiveSubscription =
        state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
            state.selectedProfileName.isNotBlank() &&
            state.selectedProfileSourceUrl != state.profileUrl
    val locations = state.currentLocations
        .mapIndexed { index, rawLink ->
            val parsed = runCatching { LocationConfigs.decodeStoredLocation(rawLink) }.getOrNull()
            SavedLocationRow(
                index = index,
                rawLink = rawLink,
                name = parsed?.remarks?.let { formatLocationLabel(state.profileSourceMode, it) } ?: "Invalid location config",
                server = parsed?.server ?: "Could not read this location",
                details = parsed?.let {
                    if (it.protocol.name == "CUSTOM") {
                        "Custom sing-box config"
                    } else {
                        listOf(it.protocol.name.lowercase(), it.serverPort.toString(), it.network, it.sni)
                            .filter { value -> value.isNotBlank() }
                            .joinToString(" • ")
                    }
                } ?: "Tap edit to fix this location",
                benchmarkDetail = stripBenchmarkLocationPrefix(
                    state.locationBenchmarkDetails[rawLink].orEmpty(),
                ),
                isValid = parsed != null,
                isSelected = rawLink == selectedLocation,
            )
        }
        .sortedWith(locationRowComparator())
    val selectedName = locations.firstOrNull { it.isSelected }?.name
        ?: state.selectedProfileName.takeIf { it.isNotBlank() }?.let { formatLocationLabel(state.profileSourceMode, it) }
    val canMutateLocations = state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS

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
                            "Location search uses the remote source saved on the Profile tab. This list is updated from it each time."
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

            if (selectedLocationOutsideActiveSubscription) {
                SubscriptionMismatchWarningCard(state)
            }

            if (canMutateLocations) {
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
            } else {
                OutlinedButton(
                    onClick = onExportLocations,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text("Export Cached Locations")
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
                                appMode = state.appMode,
                                isVpnRunning = state.isVpnRunning,
                                enabled = !state.isBusy,
                                onPrimaryAction = {
                                    if (location.isSelected) {
                                        onToggleSelectedLocationVpn()
                                    } else {
                                        onSelectLocation(location.index)
                                    }
                                },
                                onRefresh = { onBenchmarkLocation(location.index) },
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
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshActiveSubscription: () -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
) {
    val activeMode = state.profileSourceMode
    val useSubscription = activeMode == ProfileSourceMode.SUBSCRIPTION
    val clipboard = LocalClipboardManager.current
    val remoteSourcePreview = remember(useSubscription, state.profileDraft) {
        if (useSubscription) {
            RemoteSourceResolver.preview(state.profileDraft)
        } else {
            null
        }
    }

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
                    "Subscription mode is active. Finding the best location uses the active subscription below and its cached locations."
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
                        },
                    )
                }
            }
            if (useSubscription) {
                if (state.subscriptions.isNotEmpty()) {
                    ProfileHistorySection(
                        subscriptions = state.subscriptions,
                        historyNames = state.profileHistoryNames,
                        currentSource = state.profileUrl,
                        onRefreshActive = onRefreshActiveSubscription,
                        onRefreshAll = onRefreshAllSubscriptions,
                        refreshEnabled = !state.isBusy,
                        onUseEntry = onUseProfileHistoryEntry,
                        onRenameEntry = onShowProfileHistoryRenameDialog,
                        onDeleteEntry = onDeleteProfileHistoryEntry,
                    )
                }
                if (state.showAddSubscriptionEditor) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = "Add a new subscription",
                            color = Color.White,
                            fontSize = 16.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            IconButton(
                                onClick = {
                                    clipboard.getText()?.text
                                        ?.takeIf { it.isNotBlank() }
                                        ?.let { onProfileChange(it) }
                                },
                                enabled = !state.isBusy,
                                modifier = Modifier
                                    .background(Color(0x223C7AE6), RoundedCornerShape(12.dp))
                                    .size(44.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.ContentPaste,
                                    contentDescription = "Paste remote source",
                                    tint = Color.White,
                                )
                            }
                            IconButton(
                                onClick = onClearProfileSource,
                                enabled = !state.isBusy && (state.profileUrl.isNotBlank() || state.profileDraft.isNotBlank()),
                                modifier = Modifier
                                    .background(Color(0x223C7AE6), RoundedCornerShape(12.dp))
                                    .size(44.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.DeleteSweep,
                                    contentDescription = "Clear remote source",
                                    tint = Color.White,
                                )
                            }
                            IconButton(
                                onClick = onToggleAddSubscriptionEditor,
                                enabled = !state.isBusy,
                                modifier = Modifier
                                    .background(Color(0x223C7AE6), RoundedCornerShape(12.dp))
                                    .size(44.dp),
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Close,
                                    contentDescription = "Close subscription editor",
                                    tint = Color.White,
                                )
                            }
                        }
                    }
                    OutlinedTextField(
                        value = state.profileDraft,
                        onValueChange = onProfileChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 3,
                        placeholder = { Text("Paste a subscription URL or import link") },
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Paste a subscription URL or a remote import link.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                    remoteSourcePreview?.let { preview ->
                        RemoteSourcePreviewCard(preview = preview)
                    }
                    Button(
                        onClick = onSaveProfile,
                        enabled = !state.isBusy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                        colors = darkButtonColors(),
                    ) {
                        Text("Save Remote Source")
                    }
                } else {
                    AddSubscriptionLauncherCard(
                        onClick = onToggleAddSubscriptionEditor,
                    )
                }
            }
        }
    }

}

@Composable
private fun AddSubscriptionLauncherCard(
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
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun ProfileHistorySection(
    subscriptions: List<SubscriptionSource>,
    historyNames: Map<String, String>,
    currentSource: String,
    onRefreshActive: () -> Unit,
    onRefreshAll: () -> Unit,
    refreshEnabled: Boolean,
    onUseEntry: (String) -> Unit,
    onRenameEntry: (String) -> Unit,
    onDeleteEntry: (String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = "Subscriptions",
            color = Color.White,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
        )
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = onRefreshActive,
                enabled = refreshEnabled,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                colors = darkOutlinedButtonColors(),
            ) {
                Text("Refresh Active")
            }
            OutlinedButton(
                onClick = onRefreshAll,
                enabled = refreshEnabled,
                modifier = Modifier.weight(1f),
                shape = RoundedCornerShape(14.dp),
                border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                colors = darkOutlinedButtonColors(),
            ) {
                Text("Refresh All")
            }
        }
        subscriptions.forEach { subscription ->
            val source = subscription.url
            val preview = RemoteSourceResolver.preview(source)
            ProfileHistoryEntryCard(
                source = source,
                subscription = subscription,
                customName = historyNames[source].orEmpty(),
                preview = preview,
                isActive = source == currentSource,
                onUse = { onUseEntry(source) },
                onRename = { onRenameEntry(source) },
                onDelete = { onDeleteEntry(source) },
            )
        }
    }
}

@Composable
private fun ProfileHistoryEntryCard(
    source: String,
    subscription: SubscriptionSource,
    customName: String,
    preview: RemoteSourcePreview?,
    isActive: Boolean,
    onUse: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    val displayTitle = customName.ifBlank { preview?.title ?: "Saved source" }
    val defaultTitle = preview?.title.orEmpty()
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (isActive) Color(0x334B7BE5) else Color(0x24141F2D),
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(onClick = onUse)
                .padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    text = preview?.kindLabel ?: "Remote source",
                    color = if (isActive) Color(0xFFB7D3FF) else Color(0xFF9ED6FF),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = displayTitle,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (customName.isNotBlank() && defaultTitle.isNotBlank() && customName != defaultTitle) {
                    Text(
                        text = "Detected: $defaultTitle",
                        color = Color(0xFF8EA8BA),
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    text = preview?.detail ?: "Tap to use this source",
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = "Cached locations: ${subscription.cachedLocations.size} • Last refresh: ${subscription.lastRefreshedAtEpochMillis.formatAsStatusTime()}",
                    color = Color(0xFF9FB8C8),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                subscription.lastRefreshStatus.takeIf { it.isNotBlank() }?.let { status ->
                    Text(
                        text = status,
                        color = Color(0xFFFFE0A3),
                        fontSize = 11.sp,
                        maxLines = 2,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    text = RemoteSourceResolver.redactForDiagnostics(source),
                    color = Color(0xFF8EA8BA),
                    fontSize = 11.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (isActive) {
                    Text(
                        text = "Active subscription",
                        color = Color(0xFF7FE7B5),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                IconButton(onClick = onRename) {
                    Icon(
                        imageVector = Icons.Filled.Edit,
                        contentDescription = "Rename history entry",
                        tint = Color.White,
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = "Delete history entry",
                        tint = Color.White,
                    )
                }
            }
        }
    }
}

@Composable
private fun RemoteSourcePreviewCard(preview: RemoteSourcePreview) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (preview.supported) Color(0x24141F2D) else Color(0x33A06A20),
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = preview.kindLabel,
                color = if (preview.supported) Color(0xFF9ED6FF) else Color(0xFFFFD08A),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = preview.title,
                color = Color.White,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = preview.detail,
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            preview.warning?.takeIf { it.isNotBlank() }?.let { warning ->
                Text(
                    text = warning,
                    color = Color(0xFFFFE0A3),
                    fontSize = 12.sp,
                )
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
    onShowAddRuleSetDialog: () -> Unit,
    onEditRuleSet: (String) -> Unit,
    onDeleteRuleSet: (String) -> Unit,
    onCloseRuleSetDialog: () -> Unit,
    onRuleSetNameChange: (String) -> Unit,
    onRuleSetSourceChange: (String) -> Unit,
    onRuleSetSourceTypeChange: (RoutingRuleSetSourceType) -> Unit,
    onRuleSetFormatChange: (RoutingRuleSetFormat) -> Unit,
    onRuleSetActionChange: (RoutingRuleSetAction) -> Unit,
    onRuleSetUpdateHoursChange: (String) -> Unit,
    onSaveRuleSet: () -> Unit,
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
                        text = if (state.appMode == AppMode.VPN) {
                            "Choose which apps use the VPN and which domains bypass it. You can also ignore all saved rules temporarily."
                        } else {
                            "Choose which domains go direct when using proxy-only mode. App assignments are still saved for VPN mode."
                        },
                        color = Color(0xFFD3E3EE),
                        fontSize = 14.sp,
                    )
                }
            }
            item {
                CompactSummaryCard(state)
            }
            if (state.appMode == AppMode.PROXY_ONLY) {
                item {
                    ProxyOnlyRulesNoteCard()
                }
            }
            item {
                IgnoreRulesCard(
                    enabled = state.routingIgnoreRulesDraft,
                    appMode = state.appMode,
                    onEnabledChange = onIgnoreRulesChange,
                )
            }
            item {
                RuleSetSectionCard(
                    ruleSets = state.routingRuleSetsDraft,
                    onAdd = onShowAddRuleSetDialog,
                    onEdit = onEditRuleSet,
                    onDelete = onDeleteRuleSet,
                )
            }
            item {
                AppSelectionSectionCard(
                    title = "Proxy Apps",
                    count = state.routingProxyPackagesDraft.size,
                    description = if (state.appMode == AppMode.VPN) {
                        "Only these apps use the VPN. Domain bypass rules still apply."
                    } else {
                        "Saved for VPN mode only. Proxy-only mode does not support per-app routing."
                    },
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
                    description = if (state.appMode == AppMode.VPN) {
                        "These apps stay off the VPN. An app cannot be both direct and proxy."
                    } else {
                        "Saved for VPN mode only. Proxy-only mode does not support per-app routing."
                    },
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
                "${state.routingRuleSetsDraft.size} rule-sets • ${state.routingNationalDomainsDraft.countEntries()} country-code domains • " +
                    "${state.routingDirectDomainsDraft.countEntries()} bypass domains",
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
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
            if (state.isVpnRunning) {
                Text(
                    text = if (state.appMode == AppMode.VPN) {
                        "Restart the VPN after saving or importing rules."
                    } else {
                        "Restart the local proxy after saving or importing rules."
                    },
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
    appMode: AppMode,
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
                        if (appMode == AppMode.VPN) {
                            "User-defined app and domain rules are ignored. Normal app traffic goes through the VPN."
                        } else {
                            "User-defined domain rules are ignored. Proxy-only mode sends all proxied traffic through the selected connection."
                        }
                    } else {
                        if (appMode == AppMode.VPN) {
                            "User-defined app and domain rules are applied."
                        } else {
                            "User-defined domain rules are applied. App assignments stay saved for VPN mode."
                        }
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
private fun RuleSetSectionCard(
    ruleSets: List<RoutingRuleSet>,
    onAdd: () -> Unit,
    onEdit: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Rule-Sets", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                    Text(
                        text = "Attach inline or remote sing-box rule-sets and route matches to direct, proxy, or block.",
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                }
                OutlinedButton(
                    onClick = onAdd,
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
                ) {
                    Text("Add")
                }
            }
            if (ruleSets.isEmpty()) {
                Text(
                    text = "No rule-sets added yet.",
                    color = Color(0xFF9FB8C8),
                    fontSize = 12.sp,
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    ruleSets.forEach { ruleSet ->
                        RuleSetEntryCard(
                            ruleSet = ruleSet,
                            onEdit = { onEdit(ruleSet.id) },
                            onDelete = { onDelete(ruleSet.id) },
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun RuleSetEntryCard(
    ruleSet: RoutingRuleSet,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
) {
    Card(
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x1F203041)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(3.dp),
            ) {
                Text(
                    text = ruleSet.name,
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "${ruleSet.sourceType.label()} • ${ruleSet.action.label()}${if (ruleSet.sourceType == RoutingRuleSetSourceType.REMOTE) " • ${ruleSet.format.label()} • ${ruleSet.updateIntervalHours}h" else ""}",
                    color = Color(0xFF9ED6FF),
                    fontSize = 12.sp,
                )
                Text(
                    text = if (ruleSet.sourceType == RoutingRuleSetSourceType.REMOTE) ruleSet.source else "Inline rules",
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                IconButton(onClick = onEdit) {
                    Icon(
                        imageVector = Icons.Filled.Edit,
                        contentDescription = "Edit rule-set",
                        tint = Color.White,
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = "Delete rule-set",
                        tint = Color(0xFFFFC4C4),
                    )
                }
            }
        }
    }
}

@Composable
private fun RuleSetEditorDialog(
    state: MainUiState,
    onDismiss: () -> Unit,
    onNameChange: (String) -> Unit,
    onSourceChange: (String) -> Unit,
    onSourceTypeChange: (RoutingRuleSetSourceType) -> Unit,
    onFormatChange: (RoutingRuleSetFormat) -> Unit,
    onActionChange: (RoutingRuleSetAction) -> Unit,
    onUpdateHoursChange: (String) -> Unit,
    onSave: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = if (state.editingRuleSetId.isBlank()) "Add Rule-Set" else "Edit Rule-Set",
                color = Color.White,
            )
        },
        containerColor = Color(0xFF141F2D),
        textContentColor = Color.White,
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedTextField(
                    value = state.routingRuleSetNameDraft,
                    onValueChange = onNameChange,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Name") },
                    singleLine = true,
                    colors = routingTextFieldColors(),
                )
                Text("Source", color = Color.White, fontWeight = FontWeight.SemiBold)
                SourceModeOption(
                    title = "Remote",
                    description = "Download a rule-set from an HTTPS URL.",
                    selected = state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE,
                    onClick = { onSourceTypeChange(RoutingRuleSetSourceType.REMOTE) },
                )
                SourceModeOption(
                    title = "Inline",
                    description = "Paste a sing-box rules array or source-format JSON directly.",
                    selected = state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.INLINE,
                    onClick = { onSourceTypeChange(RoutingRuleSetSourceType.INLINE) },
                )
                Text("Action", color = Color.White, fontWeight = FontWeight.SemiBold)
                RoutingRuleSetAction.entries.forEach { action ->
                    SourceModeOption(
                        title = action.label(),
                        description = when (action) {
                            RoutingRuleSetAction.DIRECT -> "Send matching traffic directly."
                            RoutingRuleSetAction.PROXY -> "Send matching traffic through the selected proxy."
                            RoutingRuleSetAction.BLOCK -> "Block matching traffic."
                        },
                        selected = state.routingRuleSetActionDraft == action,
                        onClick = { onActionChange(action) },
                    )
                }
                if (state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE) {
                    Text("Format", color = Color.White, fontWeight = FontWeight.SemiBold)
                    RoutingRuleSetFormat.entries.forEach { format ->
                        SourceModeOption(
                            title = format.label(),
                            description = if (format == RoutingRuleSetFormat.SOURCE) {
                                "Use a source-format JSON rule-set."
                            } else {
                                "Use a binary .srs rule-set."
                            },
                            selected = state.routingRuleSetFormatDraft == format,
                            onClick = { onFormatChange(format) },
                        )
                    }
                }
                OutlinedTextField(
                    value = state.routingRuleSetSourceDraft,
                    onValueChange = onSourceChange,
                    modifier = Modifier.fillMaxWidth(),
                    minLines = if (state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE) 2 else 6,
                    label = {
                        Text(
                            if (state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE) {
                                "Remote URL"
                            } else {
                                "Inline JSON"
                            },
                        )
                    },
                    placeholder = {
                        Text(
                            if (state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE) {
                                "https://example.com/ruleset.json"
                            } else {
                                "{\"version\":1,\"rules\":[...]}"
                            },
                        )
                    },
                    colors = routingTextFieldColors(),
                )
                if (state.routingRuleSetSourceTypeDraft == RoutingRuleSetSourceType.REMOTE) {
                    OutlinedTextField(
                        value = state.routingRuleSetUpdateHoursDraft,
                        onValueChange = onUpdateHoursChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Update interval (hours)") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onSave) {
                Text("Save", color = Color(0xFF9ED6FF))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = Color(0xFFD3E3EE))
            }
        },
    )
}

@Composable
private fun ProxyOnlyRulesNoteCard() {
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x332A3E12)),
        border = BorderStroke(1.dp, Color(0xFFFFC857)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = "Proxy-only mode",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Only domain rules apply in proxy-only mode. App assignments are kept for when you switch back to VPN mode.",
                color = Color(0xFFFFF0CC),
                fontSize = 12.sp,
            )
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
    appMode: AppMode,
    isVpnRunning: Boolean,
    enabled: Boolean,
    onPrimaryAction: () -> Unit,
    onRefresh: () -> Unit,
    onEdit: (() -> Unit)?,
    onDelete: (() -> Unit)?,
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
                            isSelectedAndRunning -> "Stop ${connectionLabel(appMode)} for this location"
                            location.isSelected -> "Start ${connectionLabel(appMode)} for this location"
                            else -> "Select this location"
                        },
                    )
                }
                OutlinedButton(
                    onClick = onRefresh,
                    enabled = enabled && location.isValid,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = "Recheck this location",
                    )
                }
                if (onEdit != null) {
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
                }
                if (onDelete != null) {
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
}

@Composable
private fun StatusCard(state: MainUiState) {
    val activeProfile = activeProfileLabel(state)
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
            Spacer(modifier = Modifier.height(4.dp))
            Text("Selected profile: $activeProfile", color = Color(0xFFD3E3EE))
            if (state.selectedProfileName.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Selected location: ${state.selectedProfileName}",
                    color = Color(0xFFD3E3EE),
                )
                Text("Server: ${state.selectedProfileServer}", color = Color(0xFFD3E3EE))
            }
        }
    }
}

@Composable
private fun SessionCard(state: MainUiState) {
    val now by produceState(
        initialValue = System.currentTimeMillis(),
        key1 = state.isVpnRunning,
        key2 = state.sessionStartedAtEpochMillis,
    ) {
        value = System.currentTimeMillis()
        if (state.isVpnRunning) {
            while (true) {
                delay(30_000L)
                value = System.currentTimeMillis()
            }
        }
    }
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
            Text("Session", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(
                text = if (state.isVpnRunning) {
                    "Running for ${state.sessionStartedAtEpochMillis.elapsedLabel(now)}"
                } else {
                    "Stopped"
                },
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Started: ${state.sessionStartedAtEpochMillis.formatAsStatusTime()}",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Text(
                text = "Stopped: ${state.sessionStoppedAtEpochMillis.formatAsStatusTime()}",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Text(
                text = "Successful starts: ${state.successfulStarts} • Successful stops: ${state.successfulStops}",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun SubscriptionMismatchWarningCard(state: MainUiState) {
    Card(
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(3.dp, Color(0xFFFFC857)),
        colors = CardDefaults.cardColors(containerColor = Color(0x66421F0A)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = "Selected location is from a different subscription",
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
            )
            Text(
                text = "Active profile: ${activeProfileLabel(state)}",
                color = Color(0xFFFFD98A),
                fontWeight = FontWeight.SemiBold,
                fontSize = 13.sp,
            )
            Text(
                text = "Run Find Best or reconnect to switch to a location from the current subscription.",
                color = Color(0xFFFFF0CC),
                fontSize = 12.sp,
            )
        }
    }
}

private fun activeProfileLabel(state: MainUiState): String {
    return when (state.profileSourceMode) {
        ProfileSourceMode.SUBSCRIPTION -> {
            val currentSource = state.profileUrl.trim()
            val selectedSource = state.selectedProfileSourceUrl.trim()
            val activeSource = when {
                state.selectedProfileName.isNotBlank() && selectedSource.isNotBlank() -> selectedSource
                state.selectedProfileName.isNotBlank() && selectedSource.isBlank() -> ""
                currentSource.isNotBlank() -> currentSource
                else -> ""
            }
            when {
                activeSource.isNotBlank() -> profileLabelForSource(state, activeSource)
                state.selectedProfileName.isNotBlank() -> "Different subscription"
                else -> "none"
            }
        }
        ProfileSourceMode.CURRENT_LOCATIONS -> "Saved Locations"
    }
}

private fun profileLabelForSource(state: MainUiState, source: String): String {
    val trimmed = source.trim()
    if (trimmed.isBlank()) return "none"
    return state.profileHistoryNames[trimmed]
        ?.takeIf { it.isNotBlank() }
        ?: RemoteSourceResolver.preview(trimmed)?.title
        ?: "Remote source"
}

private fun formatLocationLabel(mode: ProfileSourceMode, name: String): String {
    val trimmed = name.trim()
    if (trimmed.isBlank()) return "none"
    return when (mode) {
        ProfileSourceMode.SUBSCRIPTION -> "Subscription: $trimmed"
        ProfileSourceMode.CURRENT_LOCATIONS -> "Saved location: $trimmed"
    }
}

private fun Long.formatAsStatusTime(): String {
    if (this <= 0L) return "never"
    return runCatching {
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")
            .withZone(ZoneId.systemDefault())
            .format(Instant.ofEpochMilli(this))
    }.getOrDefault("unknown")
}

private fun Long.elapsedLabel(now: Long = System.currentTimeMillis()): String {
    if (this <= 0L || now <= this) return "0m"
    val totalMinutes = ((now - this) / 60_000L).coerceAtLeast(0L)
    val hours = totalMinutes / 60
    val minutes = totalMinutes % 60
    return when {
        hours > 0 -> "${hours}h ${minutes}m"
        else -> "${minutes}m"
    }
}

@Composable
private fun ActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    sublabel: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    outlined: Boolean = false,
    colors: androidx.compose.material3.ButtonColors? = null,
) {
    val content: @Composable () -> Unit = {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
            )
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(label, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Text(sublabel)
            }
        }
    }
    if (outlined) {
        OutlinedButton(
            onClick = onClick,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(18.dp),
            shape = RoundedCornerShape(22.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = Color.White,
                disabledContentColor = Color(0xFF94A9B8),
            ),
        ) {
            content()
        }
    } else {
        Button(
            onClick = onClick,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            contentPadding = PaddingValues(18.dp),
            shape = RoundedCornerShape(22.dp),
            colors = colors ?: ButtonDefaults.buttonColors(),
        ) {
            content()
        }
    }
}

private fun routingSummary(state: MainUiState): String {
    if (state.routingRules.ignoreRules) {
        return if (state.appMode == AppMode.VPN) {
            "Ignored • all normal app traffic through VPN"
        } else {
            "Ignored • all proxied traffic through the selected proxy outbound"
        }
    }
    return buildString {
        append("${state.routingRules.proxyPackages.size} proxy")
        append(" • ")
        append("${state.routingRules.bypassPackages.size} direct")
        append(" • ")
        append("${state.routingRules.ruleSets.size} rule-sets")
        append(" • ")
        append("${state.routingRules.nationalDomainSuffixes.size} country-code domains")
        append(" • ")
        append("${state.routingRules.directDomainSuffixes.size} bypass domains")
    }
}

private fun connectionLabel(appMode: AppMode): String {
    return when (appMode) {
        AppMode.VPN -> "VPN"
        AppMode.PROXY_ONLY -> "proxy"
    }
}

private fun RoutingRuleSetSourceType.label(): String {
    return when (this) {
        RoutingRuleSetSourceType.INLINE -> "Inline"
        RoutingRuleSetSourceType.REMOTE -> "Remote"
    }
}

private fun RoutingRuleSetFormat.label(): String {
    return when (this) {
        RoutingRuleSetFormat.SOURCE -> "Source"
        RoutingRuleSetFormat.BINARY -> "Binary"
    }
}

private fun RoutingRuleSetAction.label(): String {
    return when (this) {
        RoutingRuleSetAction.DIRECT -> "Direct"
        RoutingRuleSetAction.PROXY -> "Proxy"
        RoutingRuleSetAction.BLOCK -> "Block"
    }
}

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        packageName in state.routingBypassPackagesDraft -> 1
        else -> 2
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
private fun activeVpnButtonColors() = ButtonDefaults.buttonColors(
    containerColor = Color(0xFF9A4D3A),
    contentColor = Color.White,
    disabledContainerColor = Color(0xFF5B4038),
    disabledContentColor = Color(0xFFC9B2A9),
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
