package com.kardinal.vpncontrol.ui

import android.content.Intent
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
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
import com.kardinal.vpncontrol.BuildConfig
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.RemoteSourcePreview
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SingBoxConfigFactory
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.shared.ui.HomeTabScaffold
import com.kardinal.vpncontrol.shared.ui.AppUpdateDialog
import com.kardinal.vpncontrol.shared.ui.LanguageSettingsDialog
import com.kardinal.vpncontrol.shared.ui.LocalAppStrings
import com.kardinal.vpncontrol.shared.ui.LocationsScreen as SharedLocationsScreen
import com.kardinal.vpncontrol.shared.ui.MainScreen as SharedMainScreen
import com.kardinal.vpncontrol.shared.ui.ProfileScreen as SharedProfileScreen
import com.kardinal.vpncontrol.shared.ui.RoutingRulesScreen as SharedRoutingRulesScreen
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow as SharedSavedLocationRow
import com.kardinal.vpncontrol.shared.ui.StatsScreen as SharedStatsScreen
import com.kardinal.vpncontrol.shared.ui.UiText
import com.kardinal.vpncontrol.shared.ui.activeProfileLabel as sharedActiveProfileLabel
import com.kardinal.vpncontrol.shared.ui.currentSubscriptionSelectionLabel as sharedCurrentSubscriptionSelectionLabel
import com.kardinal.vpncontrol.shared.ui.ignoreRulesDescription
import com.kardinal.vpncontrol.shared.ui.selectedLocationOutsideCurrentSubscription as sharedSelectedLocationOutsideCurrentSubscription
import com.kardinal.vpncontrol.shared.ui.rememberAppStrings
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import java.util.EnumMap
import java.util.Locale

@Composable
fun VpnControlApp(
    state: MainUiState,
    onNavigateBack: () -> Unit,
    onProfileChange: (String) -> Unit,
    onProfileTitleChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshSubscription: (String) -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
    onCloseProfileHistoryRenameDialog: () -> Unit,
    onProfileHistoryRenameUrlChange: (String) -> Unit,
    onProfileHistoryRenameDraftChange: (String) -> Unit,
    onSaveProfileHistoryRename: () -> Unit,
    onCloseLocationMutationBlockedDialog: () -> Unit,
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onDnsModeChange: (DnsMode) -> Unit,
    onDnsChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleHomeSshRouteDialog: () -> Unit,
    onHomeSshEnabledChange: (Boolean) -> Unit,
    onHomeSshHostChange: (String) -> Unit,
    onHomeSshPortChange: (String) -> Unit,
    onHomeSshUserChange: (String) -> Unit,
    onHomeSshHostKeysChange: (String) -> Unit,
    onHomeSshRelayPortChange: (String) -> Unit,
    onImportHomeSshPrivateKey: () -> Unit,
    onSaveHomeSshRoute: () -> Unit,
    onDismissHomeSshRestart: () -> Unit,
    onRestartForHomeSsh: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyChange: (SubscriptionRefreshPolicy) -> Unit,
    onFindBestAfterSubscriptionRefreshChange: (Boolean) -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onSaveSubscriptionRefreshPolicy: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationTestUrlChange: (String) -> Unit,
    onValidationBatchSizeChange: (String) -> Unit,
    onValidationSubscriptionRefreshConcurrencyChange: (String) -> Unit,
    onValidationRetryCountChange: (String) -> Unit,
    onValidationActiveVerificationWindowSizeChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleLanguageDialog: () -> Unit,
    onAppLanguageChange: (AppLanguage) -> Unit,
    onCheckAndDownloadUpdate: () -> Unit,
    onDismissOrCancelUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    onOpenUpdateReleaseNotes: (String) -> Unit,
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
    onRoutingBlockQuicUdp443Change: (Boolean) -> Unit,
    onRoutingAppSearchChange: (String) -> Unit,
    onToggleProxyRoutingApp: (String) -> Unit,
    onToggleDirectRoutingApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
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
    val systemLanguageCode = Locale.getDefault().language
    val appStrings = rememberAppStrings(state.appLanguage, systemLanguageCode)

    CompositionLocalProvider(LocalAppStrings provides appStrings) {
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
            onProfileTitleChange = onProfileTitleChange,
            onProfileSourceModeChange = onProfileSourceModeChange,
            onSaveProfile = onSaveProfile,
            onClearProfileSource = onClearProfileSource,
            onToggleAddSubscriptionEditor = onToggleAddSubscriptionEditor,
            onRefreshSubscription = onRefreshSubscription,
            onRefreshAllSubscriptions = onRefreshAllSubscriptions,
            onUseProfileHistoryEntry = onUseProfileHistoryEntry,
            onShowProfileHistoryRenameDialog = onShowProfileHistoryRenameDialog,
            onDeleteProfileHistoryEntry = onDeleteProfileHistoryEntry,
            onScanSubscriptionQr = onScanSubscriptionQr,
            onImportSubscriptionFromClipboard = onImportSubscriptionFromClipboard,
            onImportSubscriptionFromFile = onImportSubscriptionFromFile,
            onToggleDnsDialog = onToggleDnsDialog,
            onToggleHomeSshRouteDialog = onToggleHomeSshRouteDialog,
            onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
            onSubscriptionRefreshCustomHoursChange = onSubscriptionRefreshCustomHoursChange,
            onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
            onValidationTestUrlChange = onValidationTestUrlChange,
            onValidationBatchSizeChange = onValidationBatchSizeChange,
            onValidationRetryCountChange = onValidationRetryCountChange,
            onSaveValidationSettings = onSaveValidationSettings,
            onToggleLanguageDialog = onToggleLanguageDialog,
            onCheckAndDownloadUpdate = onCheckAndDownloadUpdate,
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
            onBlockQuicUdp443Change = onRoutingBlockQuicUdp443Change,
            onAppSearchChange = onRoutingAppSearchChange,
            onToggleProxyApp = onToggleProxyRoutingApp,
            onToggleDirectApp = onToggleDirectRoutingApp,
            onSelectAllProxyApps = onSelectAllProxyApps,
            onClearAllProxyApps = onClearAllProxyApps,
            onSelectAllDirectApps = onSelectAllDirectApps,
            onClearAllDirectApps = onClearAllDirectApps,
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
            onExportRoutingRules = onExportRoutingRules,
            onScanRoutingRulesQr = onScanRoutingRulesQr,
            onImportRoutingRulesFromClipboard = onImportRoutingRulesFromClipboard,
            onImportRoutingRules = onImportRoutingRules,
        )
    }

    if (showBlockingProgress) {
        BackHandler(enabled = true) {}
        RefreshProgressDialog(
            progressText = appStrings.statusMessage(state.statusMessage),
            onCancel = onCancelBusyAction,
        )
    }

    AppUpdateDialog(
        state = state.appUpdate,
        onDismiss = onDismissOrCancelUpdate,
        onRetry = onCheckAndDownloadUpdate,
        onInstall = onInstallUpdate,
        onOpenReleaseNotes = { onOpenUpdateReleaseNotes(state.appUpdate.releaseNotesUrl) },
    )

    BackHandler(
        enabled = !showBlockingProgress && (
            state.showProfileHistoryRenameDialog ||
            state.showLocationMutationBlockedDialog ||
            state.showDnsDialog ||
            state.showHomeSshRouteDialog ||
            state.showHomeSshRestartDialog ||
            state.showAppModeDialog ||
            state.showRefreshPolicyDialog ||
            state.showValidationSettingsDialog ||
            state.showLanguageDialog ||
            state.showLocationDialog ||
            state.currentScreen != AppScreen.MAIN ||
            state.screenHistory.isNotEmpty()
        ),
    ) {
        when {
            state.showProfileHistoryRenameDialog -> onCloseProfileHistoryRenameDialog()
            state.showLocationMutationBlockedDialog -> onCloseLocationMutationBlockedDialog()
            state.showDnsDialog -> onToggleDnsDialog()
            state.showHomeSshRouteDialog -> onToggleHomeSshRouteDialog()
            state.showHomeSshRestartDialog -> onDismissHomeSshRestart()
            state.showAppModeDialog -> onToggleAppModeDialog()
            state.showRefreshPolicyDialog -> onToggleRefreshPolicyDialog()
            state.showValidationSettingsDialog -> onToggleValidationSettingsDialog()
            state.showLanguageDialog -> onToggleLanguageDialog()
            state.showLocationDialog -> onCloseLocationDialog()
            else -> onNavigateBack()
        }
    }

    if (state.showLanguageDialog) {
        LanguageSettingsDialog(
            selectedLanguage = state.appLanguage,
            systemLanguageCode = systemLanguageCode,
            onSelectLanguage = onAppLanguageChange,
            onDismiss = onToggleLanguageDialog,
        )
    }

    if (state.showProfileHistoryRenameDialog) {
        AlertDialog(
            onDismissRequest = onCloseProfileHistoryRenameDialog,
            title = { Text(appStrings.get(UiText.RENAME_SUBSCRIPTION), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = state.profileHistoryRenameUrlDraft,
                        onValueChange = onProfileHistoryRenameUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.SUBSCRIPTION_URL)) },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.profileHistoryRenameDraft,
                        onValueChange = onProfileHistoryRenameDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.NAME)) },
                        placeholder = { Text(appStrings.get(UiText.MY_SUBSCRIPTION)) },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = appStrings.get(UiText.RENAME_SUBSCRIPTION_HELP),
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveProfileHistoryRename) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseProfileHistoryRenameDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showLocationMutationBlockedDialog) {
        AlertDialog(
            onDismissRequest = onCloseLocationMutationBlockedDialog,
            title = { Text(appStrings.get(UiText.READ_ONLY_LOCATION_TITLE), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Text(
                    text = appStrings.statusMessage(state.locationMutationBlockedMessage),
                    color = Color(0xFFD3E3EE),
                )
            },
            confirmButton = {
                TextButton(onClick = onCloseLocationMutationBlockedDialog) {
                    Text(appStrings.get(UiText.OK), color = Color(0xFF9ED6FF))
                }
            },
        )
    }

    if (state.showDnsDialog) {
        AlertDialog(
            onDismissRequest = onToggleDnsDialog,
            title = { Text(appStrings.get(UiText.SETTINGS_CUSTOM_DNS), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    DnsMode.entries.forEach { mode ->
                        SecureDnsModeOption(
                            label = appStrings.get(mode.uiText()),
                            selected = state.dnsModeDraft == mode,
                            onClick = { onDnsModeChange(mode) },
                        )
                    }
                    if (state.dnsSettings.legacyRawAddress.isNotBlank()) {
                        Text(
                            appStrings.get(UiText.DNS_LEGACY_MIGRATION_NOTICE),
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFFFD18B),
                        )
                    }
                    OutlinedTextField(
                        value = state.customDnsEndpointDraft,
                        onValueChange = onDnsChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.DNS_SECURE_ENDPOINT)) },
                        placeholder = {
                            Text(
                                if (state.dnsModeDraft == DnsMode.CUSTOM_DOT) {
                                    "tls://dns.example:853"
                                } else {
                                    "https://dns.example/dns-query"
                                },
                            )
                        },
                        enabled = state.dnsModeDraft != DnsMode.AUTOMATIC,
                        colors = routingTextFieldColors(),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveDns) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleDnsDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showHomeSshRouteDialog) {
        AlertDialog(
            onDismissRequest = onToggleHomeSshRouteDialog,
            title = { Text(appStrings.get(UiText.SETTINGS_HOME_SSH_ROUTE), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(appStrings.get(UiText.HOME_SSH_DESCRIPTION), color = Color(0xFFD3E3EE))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(appStrings.get(UiText.HOME_SSH_ENABLED))
                        Switch(checked = state.homeSshEnabledDraft, onCheckedChange = onHomeSshEnabledChange)
                    }
                    OutlinedTextField(
                        value = state.homeSshHostDraft,
                        onValueChange = onHomeSshHostChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.HOME_SSH_HOST)) },
                        placeholder = { Text("ssh.karapsin.com") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.homeSshPortDraft,
                        onValueChange = onHomeSshPortChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.HOME_SSH_PORT)) },
                        placeholder = { Text("228") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.homeSshUserDraft,
                        onValueChange = onHomeSshUserChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.HOME_SSH_USER)) },
                        placeholder = { Text("kardinal") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.homeSshHostKeysDraft,
                        onValueChange = onHomeSshHostKeysChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.HOME_SSH_HOST_KEYS)) },
                        supportingText = { Text(appStrings.get(UiText.HOME_SSH_HOST_KEYS_HELP)) },
                        minLines = 2,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.homeSshRelayPortDraft,
                        onValueChange = onHomeSshRelayPortChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.HOME_SSH_RELAY_PORT)) },
                        placeholder = { Text("10808") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedButton(onClick = onImportHomeSshPrivateKey, modifier = Modifier.fillMaxWidth()) {
                        Text(appStrings.get(UiText.IMPORT_PRIVATE_KEY))
                    }
                    Text(
                        appStrings.get(
                            if (state.homeSshRouteSettings.credentialVersion > 0L) {
                                UiText.HOME_SSH_KEY_IMPORTED
                            } else {
                                UiText.HOME_SSH_KEY_MISSING
                            },
                        ),
                        color = Color(0xFFD3E3EE),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveHomeSshRoute) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleHomeSshRouteDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showHomeSshRestartDialog) {
        AlertDialog(
            onDismissRequest = onDismissHomeSshRestart,
            title = { Text(appStrings.get(UiText.HOME_SSH_RESTART_TITLE), color = Color.White) },
            text = { Text(appStrings.get(UiText.HOME_SSH_RESTART_DESCRIPTION), color = Color(0xFFD3E3EE)) },
            containerColor = Color(0xFF141F2D),
            confirmButton = {
                TextButton(onClick = onRestartForHomeSsh) {
                    Text(appStrings.get(UiText.RESTART_NOW), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissHomeSshRestart) {
                    Text(appStrings.get(UiText.RESTART_LATER), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showAppModeDialog) {
        AlertDialog(
            onDismissRequest = onToggleAppModeDialog,
            title = { Text(appStrings.get(UiText.SETTINGS_PROXY_MODE), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = appStrings.get(UiText.APP_MODE_ANDROID_DESCRIPTION),
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
                                    text = if (state.appMode == AppMode.PROXY_ONLY) {
                                        appStrings.get(UiText.PROXY_ONLY)
                                    } else {
                                        appStrings.get(UiText.VPN)
                                    },
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.appMode == AppMode.PROXY_ONLY) {
                                        appStrings.get(UiText.APP_MODE_ANDROID_PROXY_DETAIL)
                                    } else {
                                        appStrings.get(UiText.APP_MODE_ANDROID_VPN_DETAIL)
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
                            text = appStrings.get(UiText.APP_MODE_ANDROID_VPN_FOOTER),
                            color = Color(0xFF9FB8C8),
                            fontSize = 12.sp,
                        )
                    }
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = onToggleAppModeDialog) {
                    Text(appStrings.get(UiText.CLOSE), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showRefreshPolicyDialog) {
        AlertDialog(
            onDismissRequest = onToggleRefreshPolicyDialog,
            title = { Text(appStrings.get(UiText.SETTINGS_SUBSCRIPTION_REFRESH), color = Color.White) },
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
                            appStrings.get(UiText.REFRESH_DESCRIPTION_ALL)
                        } else {
                            appStrings.get(UiText.REFRESH_DESCRIPTION_SELECTED)
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
                            title = appStrings.refreshPolicyTitle(policy),
                            description = when (policy) {
                                SubscriptionRefreshPolicy.OFF -> appStrings.get(UiText.REFRESH_POLICY_OFF_DESCRIPTION)
                                SubscriptionRefreshPolicy.EVERY_HOUR -> appStrings.get(UiText.REFRESH_POLICY_HOURLY_DESCRIPTION)
                                SubscriptionRefreshPolicy.CUSTOM -> appStrings.get(UiText.REFRESH_POLICY_CUSTOM_DESCRIPTION)
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
                                        appStrings.get(UiText.FIND_BEST_AFTER_REFRESH)
                                    } else {
                                        appStrings.get(UiText.KEEP_CURRENT_LOCATION_AFTER_REFRESH)
                                    },
                                    color = Color.White,
                                    fontSize = 16.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.findBestAfterSubscriptionRefreshDraft) {
                                        appStrings.get(UiText.FIND_BEST_AFTER_REFRESH_DESCRIPTION)
                                    } else {
                                        appStrings.get(UiText.KEEP_CURRENT_LOCATION_AFTER_REFRESH_DESCRIPTION)
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
                                label = { Text(appStrings.get(UiText.CUSTOM_INTERVAL_HOURS)) },
                                placeholder = { Text("0.5") },
                                singleLine = true,
                                colors = routingTextFieldColors(),
                            )
                            Text(
                                text = appStrings.get(UiText.CUSTOM_INTERVAL_HELP),
                                color = Color(0xFF9BB3C6),
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveSubscriptionRefreshPolicy) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleRefreshPolicyDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showValidationSettingsDialog) {
        AlertDialog(
            onDismissRequest = onToggleValidationSettingsDialog,
            title = { Text(appStrings.get(UiText.SETTINGS_LOCATION_TEST), color = Color.White) },
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
                            appStrings.get(UiText.VALIDATION_DESCRIPTION_ALL)
                        } else {
                            appStrings.get(UiText.VALIDATION_DESCRIPTION_SELECTED)
                        },
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                    OutlinedTextField(
                        value = state.validationTestUrlDraft,
                        onValueChange = onValidationTestUrlChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.TEST_SITE)) },
                        placeholder = { Text(appStrings.get(UiText.TEST_SITE_PLACEHOLDER)) },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationBatchSizeDraft,
                        onValueChange = onValidationBatchSizeChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.BATCH_SIZE)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationSubscriptionRefreshConcurrencyDraft,
                        onValueChange = onValidationSubscriptionRefreshConcurrencyChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.SUBSCRIPTION_REFRESH_CONCURRENCY)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationRetryCountDraft,
                        onValueChange = onValidationRetryCountChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.RETRY_COUNT)) },
                        placeholder = { Text("1") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    OutlinedTextField(
                        value = state.validationActiveVerificationWindowSizeDraft,
                        onValueChange = onValidationActiveVerificationWindowSizeChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(appStrings.get(UiText.ACTIVE_VERIFICATION_WINDOW)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = appStrings.format(
                            UiText.VALIDATION_ANDROID_SUMMARY,
                            appStrings.validationSummary(state.validationSettings),
                        ),
                        color = Color(0xFF9ED6FF),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveValidationSettings) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleValidationSettingsDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
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
                    if (state.editingLocationIndex == null) {
                        appStrings.get(UiText.ADD_LOCATION)
                    } else {
                        appStrings.get(UiText.EDIT_LOCATION)
                    },
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
                        label = { Text(appStrings.get(UiText.LOCATION_CONFIG_LABEL)) },
                        colors = routingTextFieldColors(),
                    )
                    Text(
                        text = appStrings.get(UiText.LOCATION_CONFIG_HELP),
                        color = Color(0xFFD3E3EE),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveLocation) {
                    Text(appStrings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseLocationDialog) {
                    Text(appStrings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }
    }
}

@Composable
private fun RefreshProgressDialog(
    progressText: String,
    onCancel: () -> Unit,
) {
    val strings = LocalAppStrings.current
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
                        text = progressText.ifBlank { strings.get(UiText.REFRESHING) },
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
                        Text(strings.get(UiText.CANCEL))
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
    onProfileTitleChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshSubscription: (String) -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
    onToggleDnsDialog: () -> Unit,
    onToggleHomeSshRouteDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshCustomHoursChange: (String) -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationTestUrlChange: (String) -> Unit,
    onValidationBatchSizeChange: (String) -> Unit,
    onValidationRetryCountChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleLanguageDialog: () -> Unit,
    onCheckAndDownloadUpdate: () -> Unit,
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
    onBlockQuicUdp443Change: (Boolean) -> Unit,
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onToggleDirectApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
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
    onExportRoutingRules: () -> Unit,
    onScanRoutingRulesQr: () -> Unit,
    onImportRoutingRulesFromClipboard: () -> Unit,
    onImportRoutingRules: () -> Unit,
) {
    val strings = LocalAppStrings.current
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
                    activeProfileLabel = activeProfileLabel(state, strings),
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
                            onToggleHomeSshRouteDialog = onToggleHomeSshRouteDialog,
                            onToggleRefreshPolicyDialog = onToggleRefreshPolicyDialog,
                            onToggleValidationSettingsDialog = onToggleValidationSettingsDialog,
                            onToggleLanguageDialog = onToggleLanguageDialog,
                            onCheckAndDownloadUpdate = onCheckAndDownloadUpdate,
                            onSetAppMode = onAppModeChange,
                            onIgnoreRulesChange = onIgnoreRulesChange,
                        )
                    },
                )
                AppScreen.PROFILE -> SharedProfileScreen(
                    activeProfileLabel = activeProfileLabel(state, strings),
                    currentSelectionLabel = currentSubscriptionSelectionLabel(state, strings),
                ) {
                    ProfileSourceCard(
                        state = state,
                        onProfileChange = onProfileChange,
                        onProfileTitleChange = onProfileTitleChange,
                        onProfileSourceModeChange = onProfileSourceModeChange,
                        onSaveProfile = onSaveProfile,
                        onClearProfileSource = onClearProfileSource,
                        onToggleAddSubscriptionEditor = onToggleAddSubscriptionEditor,
                        onRefreshSubscription = onRefreshSubscription,
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
                    onAppSearchChange = onAppSearchChange,
                    onToggleProxyApp = onToggleProxyApp,
                    onToggleDirectApp = onToggleDirectApp,
                    onSelectAllProxyApps = onSelectAllProxyApps,
                    onClearAllProxyApps = onClearAllProxyApps,
                    onSelectAllDirectApps = onSelectAllDirectApps,
                    onClearAllDirectApps = onClearAllDirectApps,
                    onDirectDomainsChange = onDirectDomainsChange,
                    onBlockQuicUdp443Change = onBlockQuicUdp443Change,
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
    onToggleHomeSshRouteDialog: () -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onToggleLanguageDialog: () -> Unit,
    onCheckAndDownloadUpdate: () -> Unit,
    onSetAppMode: (AppMode) -> Unit,
    onIgnoreRulesChange: (Boolean) -> Unit,
) {
    var advancedMenuExpanded by remember { mutableStateOf(false) }
    val strings = LocalAppStrings.current
    val menuContainerColor = Color(0xFF1D2B3B)
    val menuTitleColor = Color.White
    val menuSubtitleColor = Color(0xFFD3E3EE)
    val refreshScope = if (isAllSubscriptionsActive(state)) {
        strings.get(UiText.SETTINGS_ALL_SUBSCRIPTIONS)
    } else {
        strings.get(UiText.SETTINGS_SELECTED_SUBSCRIPTION)
    }

    Box {
        IconButton(onClick = { advancedMenuExpanded = true }) {
            Icon(
                imageVector = Icons.Filled.Settings,
                contentDescription = strings.get(UiText.ADDITIONAL_SETTINGS),
                tint = Color.White,
            )
        }
        DropdownMenu(
            expanded = advancedMenuExpanded,
            onDismissRequest = { advancedMenuExpanded = false },
            containerColor = menuContainerColor,
        ) {
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_HOME_SSH_ROUTE), color = menuTitleColor)
                        Text(
                            strings.get(
                                if (state.homeSshRouteSettings.enabled) UiText.SETTINGS_ENABLED else UiText.SETTINGS_DISABLED,
                            ) + if (state.homeSshRestartPending) " • ${strings.get(UiText.HOME_SSH_PENDING)}" else "",
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    advancedMenuExpanded = false
                    onToggleHomeSshRouteDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_LANGUAGE), color = menuTitleColor)
                        Text(
                            strings.languageDisplayName(state.appLanguage, Locale.getDefault().language),
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    advancedMenuExpanded = false
                    onToggleLanguageDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_VPN_PROXY_MODE), color = menuTitleColor)
                        Text(
                            if (state.appMode == AppMode.VPN) {
                                strings.get(UiText.SETTINGS_VPN_MODE)
                            } else {
                                strings.get(UiText.SETTINGS_PROXY_ONLY)
                            },
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = state.appMode == AppMode.VPN,
                        onCheckedChange = { enabled ->
                            onSetAppMode(if (enabled) AppMode.VPN else AppMode.PROXY_ONLY)
                        },
                    )
                },
                onClick = {
                    onSetAppMode(
                        if (state.appMode == AppMode.VPN) {
                            AppMode.PROXY_ONLY
                        } else {
                            AppMode.VPN
                        },
                    )
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.IGNORE_RULES), color = menuTitleColor)
                        Text(
                            ignoreRulesDescription(state, showAppAssignments = true, strings = strings),
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = !state.routingIgnoreRulesDraft,
                        onCheckedChange = { enabled ->
                            onIgnoreRulesChange(!enabled)
                        },
                    )
                },
                onClick = {
                    onIgnoreRulesChange(!state.routingIgnoreRulesDraft)
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_SUBSCRIPTION_REFRESH), color = menuTitleColor)
                        Text(
                            "${strings.refreshPolicyDisplay(state.subscriptionRefreshPolicy, state.subscriptionRefreshCustomHours)} • $refreshScope",
                            color = menuSubtitleColor,
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
                        Text(strings.get(UiText.SETTINGS_LOCATION_TEST), color = menuTitleColor)
                        Text(
                            strings.validationSummary(state.validationSettings),
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    advancedMenuExpanded = false
                    onToggleValidationSettingsDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_CUSTOM_DNS), color = menuTitleColor)
                        Text(
                            strings.get(state.dnsSettings.mode.uiText()),
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    advancedMenuExpanded = false
                    onToggleDnsDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_UPDATE), color = menuTitleColor)
                        Text(
                            strings.format(UiText.SETTINGS_CURRENT_VERSION, BuildConfig.VERSION_NAME),
                            color = menuSubtitleColor,
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    advancedMenuExpanded = false
                    onCheckAndDownloadUpdate()
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
private fun SecureDnsModeOption(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label)
    }
}

private fun DnsMode.uiText(): UiText = when (this) {
    DnsMode.AUTOMATIC -> UiText.DNS_MODE_AUTOMATIC
    DnsMode.CUSTOM_DOH -> UiText.DNS_MODE_DOH
    DnsMode.CUSTOM_DOT -> UiText.DNS_MODE_DOT
}

@Composable
private fun ImportMenuButton(
    onQrClick: () -> Unit,
    onClipboardClick: () -> Unit,
    onFileClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    label: String? = null,
) {
    var expanded by remember { mutableStateOf(false) }
    val strings = LocalAppStrings.current
    Box(modifier = modifier) {
        OutlinedButton(
            onClick = { expanded = true },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = darkOutlinedButtonColors(),
        ) {
            Text(label ?: strings.get(UiText.IMPORT))
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-qr"),
                text = { Text(strings.get(UiText.QR)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.QrCodeScanner,
                        contentDescription = strings.get(UiText.IMPORT),
                    )
                },
                onClick = {
                    expanded = false
                    onQrClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-clipboard"),
                text = { Text(strings.get(UiText.CLIPBOARD)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.ContentPaste,
                        contentDescription = strings.get(UiText.CLIPBOARD),
                    )
                },
                onClick = {
                    expanded = false
                    onClipboardClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("import-menu-file"),
                text = { Text(strings.get(UiText.FILE)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Description,
                        contentDescription = strings.get(UiText.FILE),
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
    label: String? = null,
) {
    var expanded by remember { mutableStateOf(false) }
    val strings = LocalAppStrings.current
    Box(modifier = modifier) {
        OutlinedButton(
            onClick = { expanded = true },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = darkOutlinedButtonColors(),
        ) {
            Text(label ?: strings.get(UiText.EXPORT))
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-qr"),
                text = { Text(strings.get(UiText.QR)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.QrCodeScanner,
                        contentDescription = strings.get(UiText.EXPORT),
                    )
                },
                onClick = {
                    expanded = false
                    onQrClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-clipboard"),
                text = { Text(strings.get(UiText.CLIPBOARD)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.ContentPaste,
                        contentDescription = strings.get(UiText.CLIPBOARD),
                    )
                },
                onClick = {
                    expanded = false
                    onClipboardClick()
                },
            )
            DropdownMenuItem(
                modifier = Modifier.testTag("export-menu-file"),
                text = { Text(strings.get(UiText.FILE)) },
                leadingIcon = {
                    Icon(
                        imageVector = Icons.Filled.Description,
                        contentDescription = strings.get(UiText.FILE),
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
    val strings = LocalAppStrings.current
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
                    text = strings.get(UiText.QR_GENERATION_FAILED),
                    color = Color(0xFFD3E3EE),
                )
                Text(
                    text = strings.format(UiText.BYTES_COUNT, payload.toByteArray(Charsets.UTF_8).size),
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
                TextButton(onClick = onDismiss) {
                    Text(strings.get(UiText.CLOSE))
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
        blockQuicUdp443 = state.routingBlockQuicUdp443Draft,
        proxyPackages = RoutingRules.normalizePackageNames(state.routingProxyPackagesDraft),
        bypassPackages = emptyList(),
        directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(state.routingDirectDomainsDraft),
        ruleSets = emptyList(),
    )
}

@Composable
private fun ProxyOnlyInfoCard(state: MainUiState) {
    val strings = LocalAppStrings.current
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    val proxyAddress = "127.0.0.1:${SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT}"
    val shareText = buildString {
        appendLine(strings.get(UiText.LOCAL_PROXY))
        appendLine("${strings.get(UiText.SETTINGS_PROXY_MODE)}: mixed HTTP/SOCKS")
        appendLine("${strings.get(UiText.COPY_ADDRESS)}: $proxyAddress")
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
            Text(strings.get(UiText.LOCAL_PROXY), color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(
                text = strings.get(UiText.LOCAL_PROXY_DESCRIPTION),
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
                    strings.get(UiText.PROXY_STATUS_RUNNING)
                } else {
                    strings.get(UiText.PROXY_STATUS_STOPPED)
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
                    Text(strings.get(UiText.COPY_ADDRESS))
                }
                OutlinedButton(
                    onClick = {
                        context.startActivity(
                            Intent.createChooser(
                                Intent(Intent.ACTION_SEND).apply {
                                    type = "text/plain"
                                    putExtra(Intent.EXTRA_SUBJECT, strings.get(UiText.SHARE_PROXY_ADDRESS))
                                    putExtra(Intent.EXTRA_TEXT, shareText)
                                },
                                strings.get(UiText.SHARE_PROXY_ADDRESS),
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        )
                    },
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(18.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                ) {
                    Text(strings.get(UiText.SHARE))
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
    val strings = LocalAppStrings.current
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
                name = parsed?.remarks?.let { strings.locationLabel(state.profileSourceMode, it) } ?: strings.get(UiText.INVALID_LOCATION_CONFIG),
                server = parsed?.server ?: strings.get(UiText.COULD_NOT_READ_LOCATION),
                details = parsed?.let {
                    if (it.protocol.name == "CUSTOM") {
                        strings.get(UiText.CUSTOM_SING_BOX_CONFIG)
                    } else {
                        listOf(it.protocol.name.lowercase(), it.serverPort.toString(), it.network, it.sni)
                            .filter { value -> value.isNotBlank() }
                            .joinToString(" • ")
                    }
                } ?: strings.get(UiText.TAP_EDIT_TO_FIX_LOCATION),
                benchmarkDetail = stripBenchmarkLocationPrefix(
                    state.locationBenchmarkDetails[rawLink].orEmpty(),
                ),
                isValid = parsed != null,
                isSelected = rawLink == selectedLocation,
            )
        }
        .sortedWith(locationRowComparator())
    val selectedName = locations.firstOrNull { it.isSelected }?.name
        ?: state.selectedProfileName.takeIf { it.isNotBlank() }?.let { strings.locationLabel(state.profileSourceMode, it) }
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
                    Text(strings.get(UiText.CLOSE))
                }
            },
            title = { Text(strings.get(UiText.QR_EXPORT_TOO_LARGE)) },
            text = { Text(message) },
        )
    }

    SharedLocationsScreen(
        state = state,
        locations = locations,
        selectedName = selectedName,
        activeProfileLabel = activeProfileLabel(state, strings),
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
                                exportQrError = strings.format(
                                    UiText.QR_TOO_LARGE_MESSAGE,
                                    strings.get(UiText.EXPORT_KIND_LOCATIONS),
                                    bytes,
                                )
                            } else {
                                exportQrContent = ExportQrContent(strings.get(UiText.LOCATIONS_EXPORT_TITLE), document.content)
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
                            exportQrError = strings.format(
                                UiText.QR_TOO_LARGE_MESSAGE,
                                strings.get(UiText.EXPORT_KIND_LOCATIONS),
                                bytes,
                            )
                        } else {
                            exportQrContent = ExportQrContent(strings.get(UiText.LOCATIONS_EXPORT_TITLE), document.content)
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
    onProfileTitleChange: (String) -> Unit,
    onProfileSourceModeChange: (ProfileSourceMode) -> Unit,
    onSaveProfile: () -> Unit,
    onClearProfileSource: () -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onRefreshSubscription: (String) -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
    onUseProfileHistoryEntry: (String) -> Unit,
    onShowProfileHistoryRenameDialog: (String) -> Unit,
    onDeleteProfileHistoryEntry: (String) -> Unit,
    onScanSubscriptionQr: () -> Unit,
    onImportSubscriptionFromClipboard: () -> Unit,
    onImportSubscriptionFromFile: () -> Unit,
) {
    val strings = LocalAppStrings.current
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
            Text(strings.get(UiText.PROFILE_SOURCE), color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Text(
                text = if (activeMode == ProfileSourceMode.SUBSCRIPTION) {
                    strings.get(UiText.PROFILE_SOURCE_DESCRIPTION_SUBSCRIPTION)
                } else {
                    strings.get(UiText.PROFILE_SOURCE_DESCRIPTION_SAVED)
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
                            text = if (useSubscription) strings.get(UiText.SUBSCRIPTION) else strings.get(UiText.SAVED_LOCATIONS),
                            color = Color.White,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = if (useSubscription) {
                                strings.get(UiText.PROFILE_SOURCE_USE_SAVED_HINT)
                            } else {
                                strings.get(UiText.PROFILE_SOURCE_USE_SUBSCRIPTION_HINT)
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
                        onRefreshSubscription = onRefreshSubscription,
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
                                text = strings.get(UiText.ADD_NEW_SUBSCRIPTION),
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
                                        contentDescription = strings.get(UiText.CLEAR_REMOTE_SOURCE),
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
                                        contentDescription = strings.get(UiText.CLOSE_SUBSCRIPTION_EDITOR),
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
                            placeholder = { Text(strings.get(UiText.SUBSCRIPTION_URL_PLACEHOLDER)) },
                            colors = routingTextFieldColors(),
                        )
                        OutlinedTextField(
                            value = state.profileTitleDraft,
                            onValueChange = onProfileTitleChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text(strings.get(UiText.SUBSCRIPTION_NAME)) },
                            placeholder = { Text(strings.get(UiText.OPTIONAL_CUSTOM_NAME)) },
                            singleLine = true,
                            colors = routingTextFieldColors(),
                        )
                        Text(
                            text = strings.get(UiText.SUBSCRIPTION_URL_HELP),
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
                            Text(strings.get(UiText.SAVE_REMOTE_SOURCE))
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
    val strings = LocalAppStrings.current
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
                    contentDescription = strings.get(UiText.ADD_NEW_SUBSCRIPTION),
                    tint = Color.White,
                )
            }
            Text(
                text = strings.get(UiText.ADD_NEW_SUBSCRIPTION),
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
    onRefreshSubscription: (String) -> Unit,
    onRefreshAll: () -> Unit,
    refreshEnabled: Boolean,
    onUseEntry: (String) -> Unit,
    onRenameEntry: (String) -> Unit,
    onDeleteEntry: (String) -> Unit,
) {
    val strings = LocalAppStrings.current
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            text = strings.get(UiText.SUBSCRIPTIONS),
            color = Color.White,
            fontSize = 18.sp,
            fontWeight = FontWeight.Bold,
        )
        if (subscriptions.size > 1) {
            AllSubscriptionsEntryCard(
                mergedLocationCount = mergedSubscriptionLocations(subscriptions).size,
                isActive = activeSubscriptionId == ALL_SUBSCRIPTIONS_ID,
                onUse = { onUseEntry(ALL_SUBSCRIPTIONS_ID) },
                onRefresh = onRefreshAll,
                refreshEnabled = refreshEnabled,
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
                onRefresh = { onRefreshSubscription(subscription.id) },
                onRename = { onRenameEntry(source) },
                onDelete = { onDeleteEntry(source) },
                refreshEnabled = refreshEnabled,
            )
        }
    }
}

@Composable
private fun AllSubscriptionsEntryCard(
    mergedLocationCount: Int,
    isActive: Boolean,
    onUse: () -> Unit,
    onRefresh: () -> Unit,
    refreshEnabled: Boolean,
) {
    val strings = LocalAppStrings.current
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
                    contentDescription = strings.get(UiText.ALL_SUBSCRIPTIONS),
                    tint = Color.White,
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = strings.format(
                        UiText.ALL_SUBSCRIPTIONS_TITLE,
                        strings.locationCountLabel(mergedLocationCount, merged = true),
                    ),
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = strings.get(UiText.ALL_SUBSCRIPTIONS_DESCRIPTION),
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(2.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (isActive) {
                    Box(
                        modifier = Modifier
                            .background(Color(0xFF2B4F7C), RoundedCornerShape(999.dp))
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                    ) {
                        Text(
                            text = strings.get(UiText.ACTIVE),
                            color = Color.White,
                            fontSize = 12.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
                IconButton(
                    onClick = onRefresh,
                    enabled = refreshEnabled,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = strings.get(UiText.REFRESH_ALL),
                        tint = if (refreshEnabled) Color.White else Color(0xFF9FB8C8),
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
    onRefresh: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
    refreshEnabled: Boolean,
) {
    val strings = LocalAppStrings.current
    val displayTitle = customName.ifBlank { preview?.title ?: strings.get(UiText.SAVED_SOURCE) }
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
                    text = preview?.kindLabel ?: strings.get(UiText.REMOTE_SOURCE),
                    color = if (isActive) Color(0xFFB7D3FF) else Color(0xFF9ED6FF),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    text = "$displayTitle • ${strings.locationCountLabel(subscription.cachedLocations.size)}",
                    color = Color.White,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (customName.isNotBlank() && defaultTitle.isNotBlank() && customName != defaultTitle) {
                    Text(
                        text = strings.format(UiText.DETECTED_VALUE, defaultTitle),
                        color = Color(0xFF8EA8BA),
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Text(
                    text = preview?.detail ?: strings.get(UiText.TAP_TO_USE_SOURCE),
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = strings.format(
                        UiText.LAST_REFRESH,
                        strings.statusTime(subscription.lastRefreshedAtEpochMillis),
                    ),
                    color = Color(0xFF9FB8C8),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                subscription.lastRefreshStatus.takeIf { it.isNotBlank() }?.let { status ->
                    Text(
                        text = strings.statusMessage(status),
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
                        text = strings.get(UiText.ACTIVE_SUBSCRIPTION),
                        color = Color(0xFF7FE7B5),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                IconButton(
                    onClick = onRefresh,
                    enabled = refreshEnabled,
                ) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = strings.get(UiText.REFRESH_ACTIVE),
                        tint = if (refreshEnabled) Color.White else Color(0xFF9FB8C8),
                    )
                }
                IconButton(onClick = onRename) {
                    Icon(
                        imageVector = Icons.Filled.Edit,
                        contentDescription = strings.get(UiText.RENAME_SUBSCRIPTION),
                        tint = Color.White,
                    )
                }
                IconButton(onClick = onDelete) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = strings.get(UiText.DELETE_SUBSCRIPTION),
                        tint = Color.White,
                    )
                }
            }
        }
    }
}

@Composable
private fun RemoteSourcePreviewCard(preview: RemoteSourcePreview) {
    val strings = LocalAppStrings.current
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
                text = strings.statusMessage(preview.kindLabel),
                color = if (preview.supported) Color(0xFF9ED6FF) else Color(0xFFFFD08A),
                fontSize = 12.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = strings.statusMessage(preview.title),
                color = Color.White,
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = strings.statusMessage(preview.detail),
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            preview.warning?.takeIf { it.isNotBlank() }?.let { warning ->
                Text(
                    text = strings.statusMessage(warning),
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
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onToggleDirectApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onSelectAllDirectApps: () -> Unit,
    onClearAllDirectApps: () -> Unit,
    onDirectDomainsChange: (String) -> Unit,
    onBlockQuicUdp443Change: (Boolean) -> Unit,
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
    onExport: () -> Unit,
    onScanQr: () -> Unit,
    onImportFromClipboard: () -> Unit,
    onImport: () -> Unit,
) {
    val strings = LocalAppStrings.current
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
                    Text(strings.get(UiText.CLOSE))
                }
            },
            title = { Text(strings.get(UiText.QR_EXPORT_TOO_LARGE)) },
            text = { Text(message) },
        )
    }

    SharedRoutingRulesScreen(
        state = state,
        onAppSearchChange = onAppSearchChange,
        onToggleProxyApp = onToggleProxyApp,
        onSelectAllProxyApps = onSelectAllProxyApps,
        onClearAllProxyApps = onClearAllProxyApps,
        onDirectDomainsChange = onDirectDomainsChange,
        onBlockQuicUdp443Change = onBlockQuicUdp443Change,
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
                            exportQrError = strings.format(
                                UiText.QR_TOO_LARGE_MESSAGE,
                                strings.get(UiText.EXPORT_KIND_RULES),
                                bytes,
                            )
                        } else {
                            exportQrContent = ExportQrContent(strings.get(UiText.RULES_EXPORT_TITLE), document.content)
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

private fun activeProfileLabel(state: MainUiState, strings: com.kardinal.vpncontrol.shared.ui.AppStrings): String {
    return sharedActiveProfileLabel(
        state = state,
        resolveSourceLabel = { source -> profileLabelForSource(state, source, strings) },
        strings = strings,
    )
}

private fun currentSubscriptionSelectionLabel(
    state: MainUiState,
    strings: com.kardinal.vpncontrol.shared.ui.AppStrings,
): String {
    return sharedCurrentSubscriptionSelectionLabel(
        state = state,
        resolveSourceLabel = { source -> profileLabelForSource(state, source, strings) },
        strings = strings,
    )
}

private fun profileLabelForSource(
    state: MainUiState,
    source: String,
    strings: com.kardinal.vpncontrol.shared.ui.AppStrings,
): String {
    val trimmed = source.trim()
    if (trimmed.isBlank()) return strings.get(UiText.NONE)
    if (trimmed == ALL_SUBSCRIPTIONS_ID) return strings.get(UiText.ALL_SUBSCRIPTIONS)
    return state.profileHistoryNames[trimmed]
        ?.takeIf { it.isNotBlank() }
        ?: RemoteSourceResolver.preview(trimmed)?.title
        ?: strings.get(UiText.REMOTE_SOURCE)
}

private fun isAllSubscriptionsActive(state: MainUiState): Boolean =
    isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)

private fun selectedLocationOutsideCurrentSubscription(state: MainUiState): Boolean {
    return sharedSelectedLocationOutsideCurrentSubscription(state)
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
