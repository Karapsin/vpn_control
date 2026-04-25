package com.kardinal.vpncontrol.ui

import android.content.Intent
import android.net.TrafficStats
import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
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
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QueryStats
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
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
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
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
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.RemoteSourcePreview
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SingBoxConfigFactory
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.shared.ui.HomeTabScaffold
import com.kardinal.vpncontrol.shared.ui.LocationsScreen as SharedLocationsScreen
import com.kardinal.vpncontrol.shared.ui.MainScreen as SharedMainScreen
import com.kardinal.vpncontrol.shared.ui.ProfileScreen as SharedProfileScreen
import com.kardinal.vpncontrol.shared.ui.RoutingRulesScreen as SharedRoutingRulesScreen
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow as SharedSavedLocationRow
import com.kardinal.vpncontrol.shared.ui.StatsScreen as SharedStatsScreen
import com.kardinal.vpncontrol.shared.ui.activeProfileLabel as sharedActiveProfileLabel
import com.kardinal.vpncontrol.shared.ui.connectionLabel as sharedConnectionLabel
import com.kardinal.vpncontrol.shared.ui.currentSubscriptionSelectionLabel as sharedCurrentSubscriptionSelectionLabel
import com.kardinal.vpncontrol.shared.ui.formatLocationCountLabel as sharedFormatLocationCountLabel
import com.kardinal.vpncontrol.shared.ui.formatLocationLabel as sharedFormatLocationLabel
import com.kardinal.vpncontrol.shared.ui.routingSummary as sharedRoutingSummary
import com.kardinal.vpncontrol.shared.ui.selectedLocationOutsideCurrentSubscription as sharedSelectedLocationOutsideCurrentSubscription
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.EnumMap
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
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onDnsEnabledChange: (Boolean) -> Unit,
    onDnsChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyChange: (SubscriptionRefreshPolicy) -> Unit,
    onFindBestAfterSubscriptionRefreshChange: (Boolean) -> Unit,
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
    onOpenStatsTab: () -> Unit,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onScanLocationQr: () -> Unit,
    onImportLocationFromClipboard: () -> Unit,
    onImportLocationFromFile: () -> Unit,
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
    onScanRoutingRulesQr: () -> Unit,
    onImportRoutingRulesFromClipboard: () -> Unit,
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
            onOpenStatsTab = onOpenStatsTab,
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
            onScanSubscriptionQr = onScanSubscriptionQr,
            onImportSubscriptionFromClipboard = onImportSubscriptionFromClipboard,
            onImportSubscriptionFromFile = onImportSubscriptionFromFile,
            onToggleDnsDialog = onToggleDnsDialog,
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
            onScanLocationQr = onScanLocationQr,
            onImportLocationFromClipboard = onImportLocationFromClipboard,
            onImportLocationFromFile = onImportLocationFromFile,
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
            onScanRoutingRulesQr = onScanRoutingRulesQr,
            onImportRoutingRulesFromClipboard = onImportRoutingRulesFromClipboard,
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
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(
                        text = if (isAllSubscriptionsActive(state)) {
                            "Works only when Profile Source is set to Subscription. The app will periodically redownload every saved subscription and update the merged locations list."
                        } else {
                            "Works only when Profile Source is set to Subscription. The app will periodically redownload the selected subscription and update the saved locations list."
                        },
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
                                SubscriptionRefreshPolicy.CUSTOM -> "Use a custom interval in hours. Minimum 5 minutes."
                            },
                            selected = state.subscriptionRefreshPolicyDraft == policy,
                            onClick = { onSubscriptionRefreshPolicyChange(policy) },
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
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = if (state.findBestAfterSubscriptionRefreshDraft) {
                                        "Find best after refresh"
                                    } else {
                                        "Keep current location after refresh"
                                    },
                                    color = Color.White,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.findBestAfterSubscriptionRefreshDraft) {
                                        "When already connected, rerun best-location search after a background refresh finishes."
                                    } else {
                                        "Background refresh only updates subscription caches and does not rerun best-location search."
                                    },
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            Switch(
                                checked = state.findBestAfterSubscriptionRefreshDraft,
                                onCheckedChange = onFindBestAfterSubscriptionRefreshChange,
                            )
                        }
                    }
                    if (state.subscriptionRefreshPolicyDraft == SubscriptionRefreshPolicy.CUSTOM) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedTextField(
                                value = state.subscriptionRefreshCustomHoursDraft,
                                onValueChange = onSubscriptionRefreshCustomHoursChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Custom interval (hours)") },
                                placeholder = { Text("0.5") },
                                singleLine = true,
                                colors = routingTextFieldColors(),
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
                        text = if (isAllSubscriptionsActive(state)) {
                            "The app uses these sites when testing locations. In All mode it checks the fastest locations from every saved subscription in batches: top N first, then the next N, until the secondary site works."
                        } else {
                            "The app uses these sites when testing locations. In subscription mode it checks the fastest locations from the selected subscription in batches: top N first, then the next N, until the secondary site works."
                        },
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
                    ImportMenuButton(
                        onQrClick = onScanLocationQr,
                        onClipboardClick = onImportLocationFromClipboard,
                        onFileClick = onImportLocationFromFile,
                        enabled = !state.isBusy,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = state.locationDraft,
                        onValueChange = onLocationDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        minLines = 5,
                        label = { Text("Location config (proxy link or JSON)") },
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = "Paste a vless://, trojan://, ss://, vmess://, or socks:// link, a stored location JSON object, or a full sing-box JSON config. Remote source links belong in Profile Source on the Profile tab.",
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
    onOpenStatsTab: () -> Unit,
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
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
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
    onScanLocationQr: () -> Unit,
    onImportLocationFromClipboard: () -> Unit,
    onImportLocationFromFile: () -> Unit,
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
    onScanRoutingRulesQr: () -> Unit,
    onImportRoutingRulesFromClipboard: () -> Unit,
    onImportRoutingRules: () -> Unit,
) {
    HomeTabScaffold(
        currentScreen = state.currentScreen,
        onOpenMainTab = onOpenMainTab,
        onOpenProfileTab = onOpenProfileTab,
        onOpenLocationsTab = onOpenLocationsTab,
        onOpenStatsTab = onOpenStatsTab,
        onOpenRoutingRules = onOpenRoutingRules,
        mainIcon = Icons.Filled.Home,
        profileIcon = Icons.Filled.Person,
        locationsIcon = Icons.Filled.Public,
        statsIcon = Icons.Filled.QueryStats,
        rulesIcon = Icons.Filled.Tune,
    ) {
            when (state.currentScreen) {
                AppScreen.MAIN -> SharedMainScreen(
                    state = state,
                    activeProfileLabel = activeProfileLabel(state),
                    showSubscriptionMismatchWarning = selectedLocationOutsideCurrentSubscription(state),
                    onToggleVpn = onToggleVpn,
                    onRefresh = onRefresh,
                    onExportDiagnostics = onExportDiagnostics,
                    powerIcon = Icons.Filled.PowerSettingsNew,
                    findBestIcon = Icons.Filled.MyLocation,
                    headerActions = {
                        MainAdvancedMenu(
                            state = state,
                            onToggleDnsDialog = onToggleDnsDialog,
                            onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
                            onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
                            onToggleAppModeDialog = onToggleAppModeDialog,
                        )
                    },
                )
                AppScreen.PROFILE -> SharedProfileScreen(
                    activeProfileLabel = activeProfileLabel(state),
                    currentSelectionLabel = currentSubscriptionSelectionLabel(state),
                ) {
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
                        onScanSubscriptionQr = onScanSubscriptionQr,
                        onImportSubscriptionFromClipboard = onImportSubscriptionFromClipboard,
                        onImportSubscriptionFromFile = onImportSubscriptionFromFile,
                    )
                }
                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    onShowAddLocation = onShowAddLocation,
                    onExportLocations = onExportLocations,
                    onImportLocations = onImportLocations,
                    onScanLocationQr = onScanLocationQr,
                    onImportLocationFromClipboard = onImportLocationFromClipboard,
                    onImportLocationFromFile = onImportLocationFromFile,
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
                    onScanQr = onScanRoutingRulesQr,
                    onImportFromClipboard = onImportRoutingRulesFromClipboard,
                    onImport = onImportRoutingRules,
                )
                AppScreen.STATS -> SharedStatsScreen(
                    state = state,
                )
            }
        }
}

@Composable
private fun MainAdvancedMenu(
    state: MainUiState,
    onToggleDnsDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
) {
    var advancedMenuExpanded by remember { mutableStateOf(false) }

    Box {
        IconButton(onClick = { advancedMenuExpanded = true }) {
            Icon(
                imageVector = Icons.Filled.Settings,
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
                            buildString {
                                append(
                                    state.subscriptionRefreshPolicy.displayValue(
                                        state.subscriptionRefreshCustomHours,
                                    ),
                                )
                                append(" • ")
                                append(
                                    if (isAllSubscriptionsActive(state)) {
                                        "all subscriptions"
                                    } else {
                                        "selected subscription"
                                    },
                                )
                            },
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
private fun ImportMenuButton(
    onQrClick: () -> Unit,
    onClipboardClick: () -> Unit,
    onFileClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    label: String = "Import",
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        OutlinedButton(
            onClick = { expanded = true },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = darkOutlinedButtonColors(),
        ) {
            Text(label)
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-qr"),
                text = { Text("QR") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.QrCodeScanner,
                        contentDescription = "QR import",
                    )
                },
                onClick = {
                    expanded = false
                    onQrClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-clipboard"),
                text = { Text("Clipboard") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.ContentPaste,
                        contentDescription = "Clipboard import",
                    )
                },
                onClick = {
                    expanded = false
                    onClipboardClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-file"),
                text = { Text("File") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Description,
                        contentDescription = "File import",
                    )
                },
                onClick = {
                    expanded = false
                    onFileClick()
                },
            )
        }
    }
}

private const val MAX_QR_EXPORT_BYTES = 1600

private data class ExportQrContent(
    val title: String,
    val payload: String,
)

@Composable
private fun ExportMenuButton(
    onQrClick: () -> Unit,
    onClipboardClick: () -> Unit,
    onFileClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    label: String = "Export",
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        OutlinedButton(
            onClick = { expanded = true },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = darkOutlinedButtonColors(),
        ) {
            Text(label)
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-qr"),
                text = { Text("QR") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.QrCodeScanner,
                        contentDescription = "QR export",
                    )
                },
                onClick = {
                    expanded = false
                    onQrClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-clipboard"),
                text = { Text("Clipboard") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.ContentPaste,
                        contentDescription = "Clipboard export",
                    )
                },
                onClick = {
                    expanded = false
                    onClipboardClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-file"),
                text = { Text("File") },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Description,
                        contentDescription = "File export",
                    )
                },
                onClick = {
                    expanded = false
                    onFileClick()
                },
            )
        }
    }
}

@Composable
private fun ExportQrDialog(
    title: String,
    payload: String,
    onDismiss: () -> Unit,
) {
    val bitmap = remember(payload) { generateQrBitmap(payload) }
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0xFF141F2D)),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = title,
                    color = Color.White,
                    fontSize = 22.sp,
                    fontWeight = FontWeight.Bold,
                )
                bitmap?.let {
                    Image(
                        bitmap = it.asImageBitmap(),
                        contentDescription = title,
                        modifier = Modifier.size(280.dp),
                    )
                } ?: Text(
                    text = "Could not generate QR code.",
                    color = Color(0xFFD3E3EE),
                )
                Text(
                    text = "${payload.toByteArray(Charsets.UTF_8).size} bytes",
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
                TextButton(onClick = onDismiss) {
                    Text("Close")
                }
            }
        }
    }
}

private fun generateQrBitmap(payload: String): Bitmap? {
    return runCatching {
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
            put(EncodeHintType.MARGIN, 1)
        }
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, 768, 768, hints)
        Bitmap.createBitmap(matrix.width, matrix.height, Bitmap.Config.ARGB_8888).apply {
            for (x in 0 until matrix.width) {
                for (y in 0 until matrix.height) {
                    setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
                }
            }
        }
    }.getOrNull()
}

private fun buildLocationsExportDocument(state: MainUiState): LocationsExportDocument {
    return LocationConfigs.export(state.currentLocations)
}

private fun buildEditedRoutingRules(state: MainUiState): RoutingRules {
    return RoutingRules(
        ignoreRules = state.routingIgnoreRulesDraft,
        proxyPackages = RoutingRules.normalizePackageNames(state.routingProxyPackagesDraft),
        bypassPackages = emptyList(),
        nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(state.routingNationalDomainsDraft),
        directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(state.routingDirectDomainsDraft),
        ruleSets = emptyList(),
    )
}

@Composable
private fun MainScreen(
    state: MainUiState,
    onToggleDnsDialog: () -> Unit,
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
    val selectedLocationOutsideActiveSubscription = selectedLocationOutsideCurrentSubscription(state)

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
                                imageVector = Icons.Filled.Settings,
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
                                            buildString {
                                                append(
                                                    state.subscriptionRefreshPolicy.displayValue(
                                                        state.subscriptionRefreshCustomHours,
                                                    ),
                                                )
                                                append(" • ")
                                                append(
                                                    if (isAllSubscriptionsActive(state)) {
                                                        "all subscriptions"
                                                    } else {
                                                        "selected subscription"
                                                    },
                                                )
                                            },
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
private fun LocationsScreen(
    state: MainUiState,
    onShowAddLocation: () -> Unit,
    onExportLocations: () -> Unit,
    onImportLocations: () -> Unit,
    onScanLocationQr: () -> Unit,
    onImportLocationFromClipboard: () -> Unit,
    onImportLocationFromFile: () -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    onBenchmarkLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onToggleSelectedLocationVpn: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var exportQrContent by remember { mutableStateOf<ExportQrContent?>(null) }
    var exportQrError by remember { mutableStateOf<String?>(null) }
    val selectedLocation = LocationConfigs.selectedStoredReference(
        selectedProfileJson = state.selectedProfileJson,
        selectedProfileRawLink = state.selectedProfileRawLink,
    )
    val selectedLocationOutsideActiveSubscription = selectedLocationOutsideCurrentSubscription(state)
    val locations = state.currentLocations
        .mapIndexed { index, rawLink ->
            val parsed = runCatching { LocationConfigs.decodeStoredLocation(rawLink) }.getOrNull()
            SharedSavedLocationRow(
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
    exportQrContent?.let { qr ->
        ExportQrDialog(
            title = qr.title,
            payload = qr.payload,
            onDismiss = { exportQrContent = null },
        )
    }
    exportQrError?.let { message ->
        AlertDialog(
            onDismissRequest = { exportQrError = null },
            confirmButton = {
                TextButton(onClick = { exportQrError = null }) {
                    Text("Close")
                }
            },
            title = { Text("QR Export Too Large") },
            text = { Text(message) },
        )
    }

    SharedLocationsScreen(
        state = state,
        locations = locations,
        selectedName = selectedName,
        activeProfileLabel = activeProfileLabel(state),
        showSubscriptionMismatchWarning = selectedLocationOutsideActiveSubscription,
        onShowAddLocation = onShowAddLocation.takeIf { canMutateLocations },
        onToggleSelectedLocationVpn = onToggleSelectedLocationVpn,
        onBenchmarkLocation = onBenchmarkLocation,
        onSelectLocation = onSelectLocation,
        onEditLocation = onEditLocation,
        onDeleteLocation = onDeleteLocation,
        controls = {
            if (canMutateLocations) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    ImportMenuButton(
                        onQrClick = onScanLocationQr,
                        onClipboardClick = onImportLocationFromClipboard,
                        onFileClick = onImportLocations,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                    )
                    ExportMenuButton(
                        onQrClick = {
                            val document = buildLocationsExportDocument(state)
                            val bytes = document.content.toByteArray(Charsets.UTF_8).size
                            if (bytes > MAX_QR_EXPORT_BYTES) {
                                exportQrError =
                                    "This locations export is $bytes bytes and is too large for a reliable single QR code. Use Clipboard or File instead."
                            } else {
                                exportQrContent = ExportQrContent("Locations Export", document.content)
                            }
                        },
                        onClipboardClick = {
                            val document = buildLocationsExportDocument(state)
                            clipboard.setText(AnnotatedString(document.content))
                        },
                        onFileClick = onExportLocations,
                        enabled = !state.isBusy,
                        modifier = Modifier.weight(1f),
                    )
                }
            } else {
                ExportMenuButton(
                    onQrClick = {
                        val document = buildLocationsExportDocument(state)
                        val bytes = document.content.toByteArray(Charsets.UTF_8).size
                        if (bytes > MAX_QR_EXPORT_BYTES) {
                            exportQrError =
                                "This locations export is $bytes bytes and is too large for a reliable single QR code. Use Clipboard or File instead."
                        } else {
                            exportQrContent = ExportQrContent("Locations Export", document.content)
                        }
                    },
                    onClipboardClick = {
                        val document = buildLocationsExportDocument(state)
                        clipboard.setText(AnnotatedString(document.content))
                    },
                    onFileClick = onExportLocations,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
    )
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
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
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
) {
    val activeMode = state.profileSourceMode
    val useSubscription = activeMode == ProfileSourceMode.SUBSCRIPTION
    val remoteSourcePreview = remember(useSubscription, state.profileDraft) {
        if (useSubscription) {
            RemoteSourceResolver.preview(state.profileDraft)
        } else {
            null
        }
    }
    val addSubscriptionEditorBringIntoViewRequester = remember { BringIntoViewRequester() }
    LaunchedEffect(state.showAddSubscriptionEditor) {
        if (state.showAddSubscriptionEditor) {
            withFrameNanos { }
            addSubscriptionEditorBringIntoViewRequester.bringIntoView()
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
                        activeSubscriptionId = state.activeSubscriptionId,
                        onRefreshActive = onRefreshActiveSubscription,
                        onRefreshAll = onRefreshAllSubscriptions,
                        refreshEnabled = !state.isBusy,
                        onUseEntry = onUseProfileHistoryEntry,
                        onRenameEntry = onShowProfileHistoryRenameDialog,
                        onDeleteEntry = onDeleteProfileHistoryEntry,
                    )
                }
                if (state.showAddSubscriptionEditor) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .bringIntoViewRequester(addSubscriptionEditorBringIntoViewRequester),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = "Add a new subscription",
                                color = Color.White,
                                fontSize = 16.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.weight(1f),
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
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
                        ImportMenuButton(
                            onQrClick = onScanSubscriptionQr,
                            onClipboardClick = onImportSubscriptionFromClipboard,
                            onFileClick = onImportSubscriptionFromFile,
                            enabled = !state.isBusy,
                            modifier = Modifier.fillMaxWidth(),
                        )
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
    activeSubscriptionId: String,
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
        if (subscriptions.size > 1) {
            AllSubscriptionsEntryCard(
                mergedLocationCount = mergedSubscriptionLocations(subscriptions).size,
                isActive = activeSubscriptionId == ALL_SUBSCRIPTIONS_ID,
                onUse = { onUseEntry(ALL_SUBSCRIPTIONS_ID) },
            )
        }
        subscriptions.forEach { subscription ->
            val source = subscription.url
            val preview = RemoteSourceResolver.preview(source)
            ProfileHistoryEntryCard(
                source = source,
                subscription = subscription,
                customName = historyNames[source].orEmpty(),
                preview = preview,
                isActive = activeSubscriptionId == subscription.id,
                onUse = { onUseEntry(subscription.id) },
                onRename = { onRenameEntry(source) },
                onDelete = { onDeleteEntry(source) },
            )
        }
    }
}

@Composable
private fun AllSubscriptionsEntryCard(
    mergedLocationCount: Int,
    isActive: Boolean,
    onUse: () -> Unit,
) {
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
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = "All • ${formatLocationCountLabel(mergedLocationCount, merged = true)}",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "Merge locations from every saved subscription and search across all of them.",
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
            }
            if (isActive) {
                Box(
                    modifier = Modifier
                        .background(Color(0xFF2B4F7C), RoundedCornerShape(999.dp))
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                ) {
                    Text(
                        text = "Active",
                        color = Color.White,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
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
                    text = "$displayTitle • ${formatLocationCountLabel(subscription.cachedLocations.size)}",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 2,
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
                    text = "Last refresh: ${subscription.lastRefreshedAtEpochMillis.formatAsStatusTime()}",
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
    onScanQr: () -> Unit,
    onImportFromClipboard: () -> Unit,
    onImport: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    var exportQrContent by remember { mutableStateOf<ExportQrContent?>(null) }
    var exportQrError by remember { mutableStateOf<String?>(null) }
    exportQrContent?.let { qr ->
        ExportQrDialog(
            title = qr.title,
            payload = qr.payload,
            onDismiss = { exportQrContent = null },
        )
    }
    exportQrError?.let { message ->
        AlertDialog(
            onDismissRequest = { exportQrError = null },
            confirmButton = {
                TextButton(onClick = { exportQrError = null }) {
                    Text("Close")
                }
            },
            title = { Text("QR Export Too Large") },
            text = { Text(message) },
        )
    }

    SharedRoutingRulesScreen(
        state = state,
        onIgnoreRulesChange = onIgnoreRulesChange,
        onAppSearchChange = onAppSearchChange,
        onToggleProxyApp = onToggleProxyApp,
        onSelectAllProxyApps = onSelectAllProxyApps,
        onClearAllProxyApps = onClearAllProxyApps,
        onNationalDomainsChange = onNationalDomainsChange,
        onDirectDomainsChange = onDirectDomainsChange,
        onSave = onSave,
        controls = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                ImportMenuButton(
                    onQrClick = onScanQr,
                    onClipboardClick = onImportFromClipboard,
                    onFileClick = onImport,
                    enabled = !state.isBusy,
                    modifier = Modifier.weight(1f),
                )
                ExportMenuButton(
                    onQrClick = {
                        val document = RoutingRulesTransfer.export(buildEditedRoutingRules(state))
                        val bytes = document.content.toByteArray(Charsets.UTF_8).size
                        if (bytes > MAX_QR_EXPORT_BYTES) {
                            exportQrError =
                                "This rules export is $bytes bytes and is too large for a reliable single QR code. Use Clipboard or File instead."
                        } else {
                            exportQrContent = ExportQrContent("Rules Export", document.content)
                        }
                    },
                    onClipboardClick = {
                        val document = RoutingRulesTransfer.export(buildEditedRoutingRules(state))
                        clipboard.setText(AnnotatedString(document.content))
                    },
                    onFileClick = onExport,
                    enabled = !state.isBusy,
                    modifier = Modifier.weight(1f),
                )
            }
        },
    )
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
                "${state.routingProxyPackagesDraft.size} VPN apps assigned",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "${state.routingNationalDomainsDraft.countEntries()} country-code domains • " +
                    "${state.routingDirectDomainsDraft.countEntries()} bypass domains",
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                if (state.routingIgnoreRulesDraft) {
                    "Ignore rules is on. App/domain rules are saved but not applied."
                } else {
                    "Ignore rules is off. Only assigned apps use the VPN and saved domain rules are active."
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
                            "Saved app assignments and domain rules are ignored. Normal app traffic goes through the VPN."
                        } else {
                            "User-defined domain rules are ignored. Proxy-only mode sends all proxied traffic through the selected connection."
                        }
                    } else {
                        if (appMode == AppMode.VPN) {
                            "Only assigned apps use the VPN. Saved domain rules are applied."
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
    onToggleProxy: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isProxy -> Color(0x333983FF)
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
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = if (isProxy) "VPN on" else "VPN off",
                    color = if (isProxy) Color(0xFF83B7FF) else Color(0xFFD3E3EE),
                    fontSize = 11.sp,
                )
                Switch(
                    checked = isProxy,
                    onCheckedChange = { onToggleProxy() },
                )
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
private fun LiveTrafficCard(state: MainUiState) {
    val context = LocalContext.current
    val stats by produceState(
        LiveTrafficSnapshot(),
        state.isVpnRunning,
        state.sessionStartRxBytes,
        state.sessionStartTxBytes,
    ) {
        fun currentBytes(): Pair<Long, Long> {
            val uid = context.applicationInfo.uid
            val rx = TrafficStats.getUidRxBytes(uid).takeIf { it >= 0L } ?: 0L
            val tx = TrafficStats.getUidTxBytes(uid).takeIf { it >= 0L } ?: 0L
            return rx to tx
        }

        var lastTimestamp = System.currentTimeMillis()
        var (lastRx, lastTx) = currentBytes()
        value = LiveTrafficSnapshot(
            sessionRxBytes = if (state.sessionStartRxBytes >= 0L) (lastRx - state.sessionStartRxBytes).coerceAtLeast(0L) else 0L,
            sessionTxBytes = if (state.sessionStartTxBytes >= 0L) (lastTx - state.sessionStartTxBytes).coerceAtLeast(0L) else 0L,
            rxRateBytesPerSecond = 0L,
            txRateBytesPerSecond = 0L,
        )
        while (true) {
            delay(if (state.isVpnRunning) 2_000L else 5_000L)
            val now = System.currentTimeMillis()
            val (currentRx, currentTx) = currentBytes()
            val elapsedMillis = (now - lastTimestamp).coerceAtLeast(1L)
            value = LiveTrafficSnapshot(
                sessionRxBytes = if (state.sessionStartRxBytes >= 0L) (currentRx - state.sessionStartRxBytes).coerceAtLeast(0L) else 0L,
                sessionTxBytes = if (state.sessionStartTxBytes >= 0L) (currentTx - state.sessionStartTxBytes).coerceAtLeast(0L) else 0L,
                rxRateBytesPerSecond = (((currentRx - lastRx).coerceAtLeast(0L)) * 1000L) / elapsedMillis,
                txRateBytesPerSecond = (((currentTx - lastTx).coerceAtLeast(0L)) * 1000L) / elapsedMillis,
            )
            lastTimestamp = now
            lastRx = currentRx
            lastTx = currentTx
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
            Text("Live Traffic", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(
                text = if (state.isVpnRunning) "Current session traffic" else "Waiting for an active session",
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Received: ${formatBytes(stats.sessionRxBytes)} • Sent: ${formatBytes(stats.sessionTxBytes)}",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Text(
                text = "Down rate: ${formatBytes(stats.rxRateBytesPerSecond)}/s • Up rate: ${formatBytes(stats.txRateBytesPerSecond)}/s",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun ProfileTotalsCard(profileTotals: List<ProfileTrafficTotal>) {
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
            Text("Per-Profile Totals", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            if (profileTotals.isEmpty()) {
                Text("No completed session totals yet.", color = Color(0xFFD3E3EE))
            } else {
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x1F08111F)),
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 180.dp, max = 220.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        items(profileTotals.take(24), key = { it.profileKey }) { total ->
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(total.profileName, color = Color.White, fontWeight = FontWeight.Bold)
                                Text(
                                    text = "Received ${formatBytes(total.rxBytes)} • Sent ${formatBytes(total.txBytes)}",
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                                Text(
                                    text = "Updated ${total.lastUpdatedAtEpochMillis.formatAsStatusTime()}",
                                    color = Color(0xFF9FB8C8),
                                    fontSize = 11.sp,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LatencyHistoryCard(latencyHistory: List<LatencyHistoryEntry>) {
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
            Text("Latency History", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            if (latencyHistory.isEmpty()) {
                Text("No benchmark history yet.", color = Color(0xFFD3E3EE))
            } else {
                latencyHistory.asReversed().take(12).forEach { entry ->
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(entry.profileName, color = Color.White, fontWeight = FontWeight.Bold)
                        Text(
                            text = "Primary ${entry.primaryStatus} • Secondary ${entry.secondaryStatus}",
                            color = Color(0xFFD3E3EE),
                            fontSize = 12.sp,
                        )
                        Text(
                            text = "Primary ${entry.primaryTotalMs?.let(::formatMillisText) ?: "n/a"} • Secondary ${entry.secondaryTotalMs?.let(::formatMillisText) ?: "n/a"}",
                            color = Color(0xFFD3E3EE),
                            fontSize = 12.sp,
                        )
                        Text(
                            text = entry.createdAtEpochMillis.formatAsStatusTime(),
                            color = Color(0xFF9FB8C8),
                            fontSize = 11.sp,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun ConnectionLogCard(connectionLog: List<ConnectionLogEntry>) {
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
            Text("Connection Log", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            if (connectionLog.isEmpty()) {
                Text("No recent events yet.", color = Color(0xFFD3E3EE))
            } else {
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x1F08111F)),
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 160.dp, max = 300.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        items(connectionLog.asReversed(), key = { it.id }) { entry ->
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(entry.message, color = Color.White, fontSize = 13.sp)
                                Text(
                                    text = entry.createdAtEpochMillis.formatAsStatusTime(),
                                    color = Color(0xFF9FB8C8),
                                    fontSize = 11.sp,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ConnectionTestToolsCard(
    state: MainUiState,
    onBenchmarkSelectedLocation: () -> Unit,
) {
    val selectedLocation = LocationConfigs.selectedStoredReference(
        selectedProfileJson = state.selectedProfileJson,
        selectedProfileRawLink = state.selectedProfileRawLink,
    )
    val lastResult = state.locationBenchmarkDetails[selectedLocation].orEmpty()
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
            Text("Connection Test Tools", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(
                text = if (state.selectedProfileName.isNotBlank()) {
                    "Selected location: ${state.selectedProfileName}"
                } else {
                    "No selected location"
                },
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = if (lastResult.isNotBlank()) {
                    stripBenchmarkLocationPrefix(lastResult)
                } else {
                    "Run a test to populate the latest TCP / primary / secondary result."
                },
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            OutlinedButton(
                onClick = onBenchmarkSelectedLocation,
                enabled = !state.isBusy && state.selectedProfileName.isNotBlank() && selectedLocation.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(18.dp),
                border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                colors = darkOutlinedButtonColors(),
            ) {
                Text("Test Selected Location")
            }
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
    return sharedActiveProfileLabel(state) { source ->
        profileLabelForSource(state, source)
    }
}

private fun currentSubscriptionSelectionLabel(state: MainUiState): String {
    return sharedCurrentSubscriptionSelectionLabel(state) { source ->
        profileLabelForSource(state, source)
    }
}

private fun formatLocationCountLabel(
    count: Int,
    merged: Boolean = false,
): String {
    return sharedFormatLocationCountLabel(count, merged)
}

private fun profileLabelForSource(state: MainUiState, source: String): String {
    val trimmed = source.trim()
    if (trimmed.isBlank()) return "none"
    if (trimmed == ALL_SUBSCRIPTIONS_ID) return "All subscriptions"
    return state.profileHistoryNames[trimmed]
        ?.takeIf { it.isNotBlank() }
        ?: RemoteSourceResolver.preview(trimmed)?.title
        ?: "Remote source"
}

private fun isAllSubscriptionsActive(state: MainUiState): Boolean =
    isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)

private fun selectedLocationOutsideCurrentSubscription(state: MainUiState): Boolean {
    return sharedSelectedLocationOutsideCurrentSubscription(state)
}

private fun formatLocationLabel(mode: ProfileSourceMode, name: String): String {
    return sharedFormatLocationLabel(mode, name)
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

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0L) return "0 B"
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var index = 0
    while (value >= 1024.0 && index < units.lastIndex) {
        value /= 1024.0
        index += 1
    }
    return String.format(Locale.US, if (index == 0) "%.0f %s" else "%.1f %s", value, units[index])
}

private fun formatMillisText(value: Double): String {
    return String.format(Locale.US, "%.1f ms", value)
}

private data class LiveTrafficSnapshot(
    val sessionRxBytes: Long = 0L,
    val sessionTxBytes: Long = 0L,
    val rxRateBytesPerSecond: Long = 0L,
    val txRateBytesPerSecond: Long = 0L,
)

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
    return sharedRoutingSummary(state)
}

private fun connectionLabel(appMode: AppMode): String {
    return sharedConnectionLabel(appMode)
}

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        else -> 1
    }
}

private fun locationRowComparator(): Comparator<SharedSavedLocationRow> {
    return compareBy<SharedSavedLocationRow> { locationBenchmarkRank(it.benchmarkDetail) }
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
