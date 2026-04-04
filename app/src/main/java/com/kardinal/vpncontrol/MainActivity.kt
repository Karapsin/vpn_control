package com.kardinal.vpncontrol

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.ui.VpnControlApp

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        MainViewModel.factory(applicationContext)
    }
    private var pendingRoutingRulesExport: String? = null
    private var pendingLocationsExport: String? = null
    private var pendingVpnPermissionAction: (() -> Unit)? = null
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        if (VpnService.prepare(this) == null) {
            viewModel.onVpnPermissionGranted()
            pendingVpnPermissionAction?.invoke()
        }
        pendingVpnPermissionAction = null
    }
    private val exportRoutingRulesLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        val content = pendingRoutingRulesExport
        pendingRoutingRulesExport = null
        if (uri == null || content == null) {
            viewModel.postStatus("Routing rules export canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { writer ->
                writer.write(content)
            } ?: error("Could not open export destination")
        }.onSuccess {
            viewModel.postStatus("Routing rules exported")
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to export routing rules")
        }
    }
    private val importRoutingRulesLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) {
            viewModel.postStatus("Routing rules import canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openInputStream(uri)?.bufferedReader()?.use { reader ->
                reader.readText()
            } ?: error("Could not open selected rules file")
        }.onSuccess { raw ->
            viewModel.importRoutingRules(raw)
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to import routing rules")
        }
    }
    private val exportLocationsLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        val content = pendingLocationsExport
        pendingLocationsExport = null
        if (uri == null || content == null) {
            viewModel.postStatus("Locations export canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { writer ->
                writer.write(content)
            } ?: error("Could not open export destination")
        }.onSuccess {
            viewModel.postStatus("Locations exported")
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to export locations")
        }
    }
    private val importLocationsLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) {
            viewModel.postStatus("Locations import canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openInputStream(uri)?.bufferedReader()?.use { reader ->
                reader.readText()
            } ?: error("Could not open selected locations file")
        }.onSuccess { raw ->
            viewModel.importLocations(raw)
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to import locations")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val state = viewModel.uiState.collectAsStateWithLifecycle()
            VpnControlApp(
                state = state.value,
                onNavigateBack = viewModel::navigateBack,
                onProfileChange = viewModel::onProfileDraftChanged,
                onProfileSourceModeChange = viewModel::setProfileSourceMode,
                onSaveProfile = viewModel::saveProfile,
                onClearProfileSource = viewModel::clearProfileSource,
                onToggleAddSubscriptionEditor = viewModel::toggleAddSubscriptionEditor,
                onRefreshActiveSubscription = viewModel::refreshActiveSubscriptionCache,
                onRefreshAllSubscriptions = viewModel::refreshAllSubscriptionsCaches,
                onUseProfileHistoryEntry = viewModel::useProfileHistoryEntry,
                onShowProfileHistoryRenameDialog = viewModel::showProfileHistoryRenameDialog,
                onDeleteProfileHistoryEntry = viewModel::deleteProfileHistoryEntry,
                onCloseProfileHistoryRenameDialog = viewModel::closeProfileHistoryRenameDialog,
                onProfileHistoryRenameDraftChange = viewModel::onProfileHistoryRenameDraftChanged,
                onSaveProfileHistoryRename = viewModel::saveProfileHistoryRename,
                onCloseLocationMutationBlockedDialog = viewModel::closeLocationMutationBlockedDialog,
                onToggleDnsDialog = viewModel::toggleDnsDialog,
                onToggleUiSettingsDialog = viewModel::toggleUiSettingsDialog,
                onSessionStatsEnabledChange = viewModel::setSessionStatsEnabled,
                onDnsEnabledChange = viewModel::onCustomDnsEnabledChanged,
                onDnsChange = viewModel::onDnsDraftChanged,
                onSaveDns = viewModel::saveDns,
                onToggleRefreshPolicyDialog = viewModel::toggleRefreshPolicyDialog,
                onSubscriptionRefreshPolicyChange = viewModel::onSubscriptionRefreshPolicyDraftChanged,
                onSubscriptionRefreshCustomHoursChange = viewModel::onSubscriptionRefreshCustomHoursDraftChanged,
                onSaveSubscriptionRefreshPolicy = viewModel::saveSubscriptionRefreshPolicy,
                onToggleValidationSettingsDialog = viewModel::toggleValidationSettingsDialog,
                onValidationPrimaryUrlChange = viewModel::onValidationPrimaryUrlDraftChanged,
                onValidationSecondaryUrlChange = viewModel::onValidationSecondaryUrlDraftChanged,
                onValidationBatchSizeChange = viewModel::onValidationBatchSizeDraftChanged,
                onValidationRetryCountChange = viewModel::onValidationRetryCountDraftChanged,
                onSaveValidationSettings = viewModel::saveValidationSettings,
                onToggleAppModeDialog = viewModel::toggleAppModeDialog,
                onAppModeChange = viewModel::setAppMode,
                onOpenMainTab = viewModel::openMainTab,
                onOpenProfileTab = viewModel::openProfileTab,
                onOpenLocationsTab = viewModel::openLocationsTab,
                onOpenRoutingRules = viewModel::openRoutingRules,
                onShowAddLocation = viewModel::showAddLocationDialog,
                onExportLocations = {
                    val document = viewModel.buildLocationsExport()
                    pendingLocationsExport = document.content
                    exportLocationsLauncher.launch(document.fileName)
                },
                onImportLocations = {
                    importLocationsLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
                onEditLocation = viewModel::editLocation,
                onDeleteLocation = viewModel::deleteLocation,
                onBenchmarkLocation = viewModel::benchmarkLocation,
                onSelectLocation = viewModel::selectLocation,
                onToggleSelectedLocationVpn = {
                    if (state.value.appMode == AppMode.VPN) {
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            pendingVpnPermissionAction = { viewModel.toggleVpn() }
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            viewModel.toggleVpn()
                        }
                    } else {
                        viewModel.toggleVpn()
                    }
                },
                onCloseLocationDialog = viewModel::closeLocationDialog,
                onLocationDraftChange = viewModel::onLocationDraftChanged,
                onSaveLocation = viewModel::saveLocation,
                onRoutingIgnoreRulesChange = viewModel::onRoutingIgnoreRulesDraftChanged,
                onRoutingAppSearchChange = viewModel::onRoutingAppSearchChanged,
                onToggleProxyRoutingApp = viewModel::toggleProxyRoutingApp,
                onToggleDirectRoutingApp = viewModel::toggleDirectRoutingApp,
                onSelectAllProxyApps = viewModel::selectAllVisibleProxyApps,
                onClearAllProxyApps = viewModel::clearAllVisibleProxyApps,
                onSelectAllDirectApps = viewModel::selectAllVisibleDirectApps,
                onClearAllDirectApps = viewModel::clearAllVisibleDirectApps,
                onRoutingNationalDomainsChange = viewModel::onRoutingNationalDomainsDraftChanged,
                onRoutingDirectDomainsChange = viewModel::onRoutingDirectDomainsDraftChanged,
                onShowAddRuleSetDialog = viewModel::showAddRuleSetDialog,
                onEditRuleSet = viewModel::editRuleSet,
                onDeleteRuleSet = viewModel::deleteRuleSet,
                onCloseRuleSetDialog = viewModel::closeRuleSetDialog,
                onRuleSetNameChange = viewModel::onRuleSetNameDraftChanged,
                onRuleSetSourceChange = viewModel::onRuleSetSourceDraftChanged,
                onRuleSetSourceTypeChange = viewModel::onRuleSetSourceTypeDraftChanged,
                onRuleSetFormatChange = viewModel::onRuleSetFormatDraftChanged,
                onRuleSetActionChange = viewModel::onRuleSetActionDraftChanged,
                onRuleSetUpdateHoursChange = viewModel::onRuleSetUpdateHoursDraftChanged,
                onSaveRuleSet = viewModel::saveRuleSet,
                onSaveRoutingRules = viewModel::saveRoutingRules,
                onExportRoutingRules = {
                    val document = viewModel.buildRoutingRulesExport()
                    pendingRoutingRulesExport = document.content
                    exportRoutingRulesLauncher.launch(document.fileName)
                },
                onImportRoutingRules = {
                    importRoutingRulesLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
                onToggleVpn = {
                    if (state.value.appMode == AppMode.VPN) {
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            pendingVpnPermissionAction = { viewModel.toggleVpn() }
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            viewModel.toggleVpn()
                        }
                    } else {
                        viewModel.toggleVpn()
                    }
                },
                onRefresh = {
                    if (state.value.appMode == AppMode.VPN) {
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            pendingVpnPermissionAction = { viewModel.refresh() }
                            vpnPermissionLauncher.launch(prepareIntent)
                        } else {
                            viewModel.refresh()
                        }
                    } else {
                        viewModel.refresh()
                    }
                },
                onCancelBusyAction = viewModel::cancelActiveOperation,
                onExportDiagnostics = viewModel::exportDiagnostics,
            )
        }

        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (VpnService.prepare(this) == null) {
            viewModel.onVpnPermissionGranted()
        }
    }

    private fun handleIncomingIntent(intent: Intent?) {
        if (intent == null) return
        val sharedText = when (intent.action) {
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            else -> null
        }?.trim().orEmpty()
        if (sharedText.isNotBlank()) {
            viewModel.handleIncomingSharedText(sharedText)
            intent.removeExtra(Intent.EXTRA_TEXT)
        }
    }
}
