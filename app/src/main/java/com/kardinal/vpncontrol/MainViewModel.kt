package com.kardinal.vpncontrol

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.kardinal.vpncontrol.data.AppRepository
import com.kardinal.vpncontrol.data.BenchmarkOrchestrator
import com.kardinal.vpncontrol.data.DiagnosticsExporter
import com.kardinal.vpncontrol.data.InstalledAppsCatalog
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.IncomingImportPayload
import com.kardinal.vpncontrol.data.IncomingImportResolver
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SubscriptionRefreshScheduler
import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.MIN_SUBSCRIPTION_REFRESH_MINUTES
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.normalizeSubscriptionRefreshCustomHours
import java.net.URI
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class AppScreen {
    MAIN,
    PROFILE,
    LOCATIONS,
    ROUTING_RULES,
    STATS,
}

data class MainUiState(
    val currentScreen: AppScreen = AppScreen.MAIN,
    val screenHistory: List<AppScreen> = emptyList(),
    val profileUrl: String = "",
    val activeSubscriptionId: String = "",
    val subscriptions: List<SubscriptionSource> = emptyList(),
    val profileHistory: List<String> = emptyList(),
    val profileHistoryNames: Map<String, String> = emptyMap(),
    val profileDraft: String = "",
    val showAddSubscriptionEditor: Boolean = false,
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val appMode: AppMode = AppMode.VPN,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshPolicyDraft: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val findBestAfterSubscriptionRefresh: Boolean = true,
    val findBestAfterSubscriptionRefreshDraft: Boolean = true,
    val subscriptionRefreshCustomHours: Double = DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS,
    val subscriptionRefreshCustomHoursDraft: String = "3",
    val validationSettings: BenchmarkValidationSettings = BenchmarkValidationSettings(),
    val validationPrimaryUrlDraft: String = BenchmarkValidationSettings.DEFAULT_PRIMARY_URL,
    val validationSecondaryUrlDraft: String = BenchmarkValidationSettings.DEFAULT_SECONDARY_URL,
    val validationBatchSizeDraft: String = BenchmarkValidationSettings.DEFAULT_BATCH_SIZE.toString(),
    val validationRetryCountDraft: String = BenchmarkValidationSettings.DEFAULT_RETRY_COUNT.toString(),
    val currentLocations: List<String> = emptyList(),
    val locationBenchmarkDetails: Map<String, String> = emptyMap(),
    val customDns: String = "",
    val customDnsDraft: String = "",
    val useCustomDns: Boolean = false,
    val useCustomDnsDraft: Boolean = false,
    val routingRules: RoutingRules = RoutingRules(),
    val routingIgnoreRulesDraft: Boolean = false,
    val routingProxyPackagesDraft: Set<String> = emptySet(),
    val routingBypassPackagesDraft: Set<String> = emptySet(),
    val routingNationalDomainsDraft: String = "",
    val routingDirectDomainsDraft: String = "",
    val routingRuleSetsDraft: List<RoutingRuleSet> = emptyList(),
    val routingAppSearch: String = "",
    val installedApps: List<InstalledApp> = emptyList(),
    val installedAppsLoaded: Boolean = false,
    val installedAppsLoading: Boolean = false,
    val isVpnRunning: Boolean = false,
    val isBusy: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStartingVpn: Boolean = false,
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val selectedProfileRawLink: String = "",
    val selectedProfileJson: String = "",
    val selectedProfileSourceUrl: String = "",
    val lastBenchmarkSummary: String = "",
    val statusMessage: String = "Idle",
    val sessionStatsEnabled: Boolean = false,
    val liveTrafficStatsEnabled: Boolean = false,
    val profileTotalsEnabled: Boolean = false,
    val latencyHistoryEnabled: Boolean = false,
    val connectionLogEnabled: Boolean = false,
    val connectionTestToolsEnabled: Boolean = false,
    val sessionStartedAtEpochMillis: Long = 0L,
    val sessionStoppedAtEpochMillis: Long = 0L,
    val sessionStartRxBytes: Long = -1L,
    val sessionStartTxBytes: Long = -1L,
    val successfulStarts: Int = 0,
    val successfulStops: Int = 0,
    val profileTrafficTotals: List<ProfileTrafficTotal> = emptyList(),
    val latencyHistory: List<LatencyHistoryEntry> = emptyList(),
    val connectionLog: List<ConnectionLogEntry> = emptyList(),
    val showDnsDialog: Boolean = false,
    val showUiSettingsDialog: Boolean = false,
    val showAppModeDialog: Boolean = false,
    val showRefreshPolicyDialog: Boolean = false,
    val showValidationSettingsDialog: Boolean = false,
    val showProfileHistoryRenameDialog: Boolean = false,
    val showRuleSetDialog: Boolean = false,
    val editingRuleSetId: String = "",
    val routingRuleSetNameDraft: String = "",
    val routingRuleSetSourceDraft: String = "",
    val routingRuleSetSourceTypeDraft: RoutingRuleSetSourceType = RoutingRuleSetSourceType.REMOTE,
    val routingRuleSetFormatDraft: RoutingRuleSetFormat = RoutingRuleSetFormat.SOURCE,
    val routingRuleSetActionDraft: RoutingRuleSetAction = RoutingRuleSetAction.DIRECT,
    val routingRuleSetUpdateHoursDraft: String = "24",
    val profileHistoryRenameSource: String = "",
    val profileHistoryRenameDraft: String = "",
    val showLocationMutationBlockedDialog: Boolean = false,
    val locationMutationBlockedMessage: String = "",
    val showLocationDialog: Boolean = false,
    val locationDraft: String = "",
    val editingLocationIndex: Int? = null,
    val hasVpnPermission: Boolean = false,
)

private enum class SelectionCommitStage {
    SUCCESS,
    APPLY_FAILED,
    PERSIST_FAILED_WITHOUT_APPLY,
    PERSIST_FAILED_AFTER_APPLY,
}

private data class SelectionCommitResult(
    val stage: SelectionCommitStage,
    val error: Throwable? = null,
) {
    val isSuccess: Boolean
        get() = stage == SelectionCommitStage.SUCCESS

    val shouldRestoreSnapshot: Boolean
        get() = stage == SelectionCommitStage.APPLY_FAILED ||
            stage == SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY

    val requiresLiveRollback: Boolean
        get() = stage == SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY
}

class MainViewModel(
    private val repository: AppRepository,
    private val vpnManager: VpnManager,
    private val diagnosticsExporter: DiagnosticsExporter,
    private val installedAppsCatalog: InstalledAppsCatalog,
) : ViewModel() {
    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()
    private var activeBusyJob: Job? = null

    init {
        repository.state.onEach { persisted ->
            _uiState.value = _uiState.value.copy(
                profileUrl = persisted.profileUrl,
                activeSubscriptionId = persisted.activeSubscriptionId,
                subscriptions = persisted.subscriptions,
                profileHistory = persisted.profileHistory,
                profileHistoryNames = persisted.profileHistoryNames,
                profileDraft = if (_uiState.value.currentScreen == AppScreen.PROFILE) {
                    _uiState.value.profileDraft
                } else {
                    persisted.profileUrl
                },
                profileSourceMode = persisted.profileSourceMode,
                appMode = persisted.appMode,
                subscriptionRefreshPolicy = persisted.subscriptionRefreshPolicy,
                subscriptionRefreshPolicyDraft = if (_uiState.value.showRefreshPolicyDialog) {
                    _uiState.value.subscriptionRefreshPolicyDraft
                } else {
                    persisted.subscriptionRefreshPolicy
                },
                findBestAfterSubscriptionRefresh = persisted.findBestAfterSubscriptionRefresh,
                findBestAfterSubscriptionRefreshDraft = if (_uiState.value.showRefreshPolicyDialog) {
                    _uiState.value.findBestAfterSubscriptionRefreshDraft
                } else {
                    persisted.findBestAfterSubscriptionRefresh
                },
                subscriptionRefreshCustomHours = persisted.subscriptionRefreshCustomHours,
                subscriptionRefreshCustomHoursDraft = if (_uiState.value.showRefreshPolicyDialog) {
                    _uiState.value.subscriptionRefreshCustomHoursDraft
                } else {
                    formatSubscriptionRefreshHoursInput(persisted.subscriptionRefreshCustomHours)
                },
                validationSettings = persisted.validationSettings,
                validationPrimaryUrlDraft = if (_uiState.value.showValidationSettingsDialog) {
                    _uiState.value.validationPrimaryUrlDraft
                } else {
                    persisted.validationSettings.primaryUrl
                },
                validationSecondaryUrlDraft = if (_uiState.value.showValidationSettingsDialog) {
                    _uiState.value.validationSecondaryUrlDraft
                } else {
                    persisted.validationSettings.secondaryUrl
                },
                validationBatchSizeDraft = if (_uiState.value.showValidationSettingsDialog) {
                    _uiState.value.validationBatchSizeDraft
                } else {
                    persisted.validationSettings.batchSize.toString()
                },
                validationRetryCountDraft = if (_uiState.value.showValidationSettingsDialog) {
                    _uiState.value.validationRetryCountDraft
                } else {
                    persisted.validationSettings.retryCount.toString()
                },
                currentLocations = persisted.currentLocations,
                locationBenchmarkDetails = persisted.locationBenchmarkDetails,
                customDns = persisted.customDns,
                customDnsDraft = if (_uiState.value.showDnsDialog) _uiState.value.customDnsDraft else persisted.customDns,
                useCustomDns = persisted.useCustomDns,
                useCustomDnsDraft = if (_uiState.value.showDnsDialog) _uiState.value.useCustomDnsDraft else persisted.useCustomDns,
                routingRules = persisted.routingRules,
                routingIgnoreRulesDraft = if (_uiState.value.currentScreen == AppScreen.ROUTING_RULES) {
                    _uiState.value.routingIgnoreRulesDraft
                } else {
                    persisted.routingRules.ignoreRules
                },
                routingRuleSetsDraft = if (_uiState.value.currentScreen == AppScreen.ROUTING_RULES) {
                    _uiState.value.routingRuleSetsDraft
                } else {
                    persisted.routingRules.ruleSets
                },
                selectedProfileName = persisted.selectedProfileName,
                selectedProfileServer = persisted.selectedProfileServer,
                selectedProfileRawLink = persisted.selectedProfileRawLink,
                selectedProfileJson = persisted.selectedProfileJson,
                selectedProfileSourceUrl = persisted.selectedProfileSourceUrl,
                lastBenchmarkSummary = persisted.lastBenchmarkSummary,
                isVpnRunning = persisted.isVpnRunning,
                statusMessage = persisted.statusMessage,
                sessionStatsEnabled = persisted.sessionStatsEnabled,
                liveTrafficStatsEnabled = persisted.liveTrafficStatsEnabled,
                profileTotalsEnabled = persisted.profileTotalsEnabled,
                latencyHistoryEnabled = persisted.latencyHistoryEnabled,
                connectionLogEnabled = persisted.connectionLogEnabled,
                connectionTestToolsEnabled = persisted.connectionTestToolsEnabled,
                sessionStartedAtEpochMillis = persisted.sessionStartedAtEpochMillis,
                sessionStoppedAtEpochMillis = persisted.sessionStoppedAtEpochMillis,
                sessionStartRxBytes = persisted.sessionStartRxBytes,
                sessionStartTxBytes = persisted.sessionStartTxBytes,
                successfulStarts = persisted.successfulStarts,
                successfulStops = persisted.successfulStops,
                profileTrafficTotals = persisted.profileTrafficTotals,
                latencyHistory = persisted.latencyHistory,
                connectionLog = persisted.connectionLog,
                screenHistory = _uiState.value.screenHistory,
            )
        }.launchIn(viewModelScope)

        viewModelScope.launch {
            repository.syncSubscriptionRefreshScheduling()
        }
    }

    fun toggleDnsDialog() {
        _uiState.value = _uiState.value.copy(
            showDnsDialog = !_uiState.value.showDnsDialog,
            customDnsDraft = _uiState.value.customDns,
            useCustomDnsDraft = _uiState.value.useCustomDns,
        )
    }

    fun toggleUiSettingsDialog() {
        _uiState.value = _uiState.value.copy(
            showUiSettingsDialog = !_uiState.value.showUiSettingsDialog,
        )
    }

    fun setSessionStatsEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(sessionStatsEnabled = enabled)
        viewModelScope.launch {
            repository.updateSessionStatsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Session stats enabled" else "Session stats hidden",
            )
        }
    }

    fun setLiveTrafficStatsEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(liveTrafficStatsEnabled = enabled)
        viewModelScope.launch {
            repository.updateLiveTrafficStatsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Live traffic stats enabled" else "Live traffic stats hidden",
            )
        }
    }

    fun setProfileTotalsEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(profileTotalsEnabled = enabled)
        viewModelScope.launch {
            repository.updateProfileTotalsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Per-profile totals enabled" else "Per-profile totals hidden",
            )
        }
    }

    fun setLatencyHistoryEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(latencyHistoryEnabled = enabled)
        viewModelScope.launch {
            repository.updateLatencyHistoryEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Latency history enabled" else "Latency history hidden",
            )
        }
    }

    fun setConnectionLogEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(connectionLogEnabled = enabled)
        viewModelScope.launch {
            repository.updateConnectionLogEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Connection log enabled" else "Connection log hidden",
            )
        }
    }

    fun setConnectionTestToolsEnabled(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(connectionTestToolsEnabled = enabled)
        viewModelScope.launch {
            repository.updateConnectionTestToolsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Connection test tools enabled" else "Connection test tools hidden",
            )
        }
    }

    fun toggleAppModeDialog() {
        _uiState.value = _uiState.value.copy(
            showAppModeDialog = !_uiState.value.showAppModeDialog,
        )
    }

    fun toggleRefreshPolicyDialog() {
        _uiState.value = _uiState.value.copy(
            showRefreshPolicyDialog = !_uiState.value.showRefreshPolicyDialog,
            subscriptionRefreshPolicyDraft = _uiState.value.subscriptionRefreshPolicy,
            findBestAfterSubscriptionRefreshDraft = _uiState.value.findBestAfterSubscriptionRefresh,
            subscriptionRefreshCustomHoursDraft = formatSubscriptionRefreshHoursInput(
                _uiState.value.subscriptionRefreshCustomHours,
            ),
        )
    }

    fun toggleValidationSettingsDialog() {
        val current = _uiState.value.validationSettings
        _uiState.value = _uiState.value.copy(
            showValidationSettingsDialog = !_uiState.value.showValidationSettingsDialog,
            validationPrimaryUrlDraft = current.primaryUrl,
            validationSecondaryUrlDraft = current.secondaryUrl,
            validationBatchSizeDraft = current.batchSize.toString(),
            validationRetryCountDraft = current.retryCount.toString(),
        )
    }

    fun openRoutingRules() {
        val rules = _uiState.value.routingRules
        _uiState.value = _uiState.value.copy(
            routingIgnoreRulesDraft = rules.ignoreRules,
            routingProxyPackagesDraft = rules.proxyPackages.toSet(),
            routingBypassPackagesDraft = emptySet(),
            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
            routingRuleSetsDraft = rules.ruleSets,
            routingAppSearch = "",
            showRuleSetDialog = false,
        )
        ensureInstalledAppsLoaded()
        navigateToScreen(AppScreen.ROUTING_RULES)
    }

    fun openMainTab() {
        navigateToScreen(AppScreen.MAIN)
    }

    fun openProfileTab() {
        navigateToScreen(AppScreen.PROFILE)
    }

    fun openLocationsTab() {
        navigateToScreen(AppScreen.LOCATIONS)
    }

    fun openStatsTab() {
        navigateToScreen(AppScreen.STATS)
    }

    fun navigateBack() {
        val history = _uiState.value.screenHistory
        when {
            history.isNotEmpty() -> {
                val target = history.last()
                _uiState.value = _uiState.value.copy(
                    currentScreen = target,
                    screenHistory = history.dropLast(1),
                    profileDraft = if (target == AppScreen.PROFILE) _uiState.value.profileUrl else _uiState.value.profileDraft,
                )
                if (target == AppScreen.ROUTING_RULES) {
                    ensureInstalledAppsLoaded()
                }
            }
            _uiState.value.currentScreen != AppScreen.MAIN -> {
                _uiState.value = _uiState.value.copy(currentScreen = AppScreen.MAIN)
            }
        }
    }

    fun onProfileDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(profileDraft = value)
    }

    fun pasteSubscriptionDraft(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) {
            viewModelScope.launch {
                repository.updateStatus("Clipboard is empty")
            }
            return
        }
        navigateToScreen(AppScreen.PROFILE)
        _uiState.value = _uiState.value.copy(
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            profileDraft = trimmed,
            showAddSubscriptionEditor = true,
        )
        viewModelScope.launch {
            repository.updateProfileSourceMode(ProfileSourceMode.SUBSCRIPTION)
            repository.updateStatus("Subscription text loaded into the Profile tab")
        }
    }

    fun toggleAddSubscriptionEditor() {
        val opening = !_uiState.value.showAddSubscriptionEditor
        _uiState.value = _uiState.value.copy(
            showAddSubscriptionEditor = opening,
            profileDraft = if (
                opening &&
                _uiState.value.profileDraft == _uiState.value.profileUrl
            ) {
                ""
            } else {
                _uiState.value.profileDraft
            },
        )
    }

    fun showProfileHistoryRenameDialog(source: String) {
        val normalized = source.trim()
        val currentName = _uiState.value.profileHistoryNames[normalized]
            ?.takeIf { it.isNotBlank() }
            ?: RemoteSourceResolver.preview(normalized)?.title
            .orEmpty()
        _uiState.value = _uiState.value.copy(
            showProfileHistoryRenameDialog = true,
            profileHistoryRenameSource = normalized,
            profileHistoryRenameDraft = currentName,
        )
    }

    fun closeProfileHistoryRenameDialog() {
        _uiState.value = _uiState.value.copy(
            showProfileHistoryRenameDialog = false,
            profileHistoryRenameSource = "",
            profileHistoryRenameDraft = "",
        )
    }

    fun onProfileHistoryRenameDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(profileHistoryRenameDraft = value.take(80))
    }

    fun setProfileSourceMode(value: ProfileSourceMode) {
        _uiState.value = _uiState.value.copy(
            profileSourceMode = value,
            profileDraft = _uiState.value.profileUrl,
            showAddSubscriptionEditor = false,
        )
        viewModelScope.launch {
            repository.updateProfileSourceMode(value)
            repository.updateStatus(
                when (value) {
                    ProfileSourceMode.SUBSCRIPTION -> "Profile source set to subscription"
                    ProfileSourceMode.CURRENT_LOCATIONS -> "Profile source set to saved locations"
                },
            )
        }
    }

    fun setAppMode(value: AppMode) {
        if (_uiState.value.isVpnRunning) {
            viewModelScope.launch {
                repository.updateStatus("Disconnect first to change connection mode")
            }
            return
        }
        _uiState.value = _uiState.value.copy(appMode = value)
        viewModelScope.launch {
            repository.updateAppMode(value)
            repository.updateStatus(
                when (value) {
                    AppMode.VPN -> "Connection mode set to VPN"
                    AppMode.PROXY_ONLY -> "Connection mode set to proxy only"
                },
            )
            _uiState.value = _uiState.value.copy(showAppModeDialog = false)
        }
    }

    fun onDnsDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(customDnsDraft = value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(useCustomDnsDraft = enabled)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        _uiState.value = _uiState.value.copy(subscriptionRefreshPolicyDraft = policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(findBestAfterSubscriptionRefreshDraft = enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(
            subscriptionRefreshCustomHoursDraft = sanitizeDecimalInput(value).take(6),
        )
    }

    fun onValidationPrimaryUrlDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(validationPrimaryUrlDraft = value)
    }

    fun onValidationSecondaryUrlDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(validationSecondaryUrlDraft = value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(
            validationBatchSizeDraft = value.filter { it.isDigit() }.take(3),
        )
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(
            validationRetryCountDraft = value.filter { it.isDigit() }.take(3),
        )
    }

    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(routingIgnoreRulesDraft = enabled)
    }

    fun onRoutingAppSearchChanged(value: String) {
        _uiState.value = _uiState.value.copy(routingAppSearch = value)
    }

    fun onRoutingNationalDomainsDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(routingNationalDomainsDraft = value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(routingDirectDomainsDraft = value)
    }

    fun showAddRuleSetDialog() {
        _uiState.value = _uiState.value.copy(
            showRuleSetDialog = true,
            editingRuleSetId = "",
            routingRuleSetNameDraft = "",
            routingRuleSetSourceDraft = "",
            routingRuleSetSourceTypeDraft = RoutingRuleSetSourceType.REMOTE,
            routingRuleSetFormatDraft = RoutingRuleSetFormat.SOURCE,
            routingRuleSetActionDraft = RoutingRuleSetAction.DIRECT,
            routingRuleSetUpdateHoursDraft = "24",
        )
    }

    fun editRuleSet(id: String) {
        val ruleSet = _uiState.value.routingRuleSetsDraft.firstOrNull { it.id == id } ?: return
        _uiState.value = _uiState.value.copy(
            showRuleSetDialog = true,
            editingRuleSetId = ruleSet.id,
            routingRuleSetNameDraft = ruleSet.name,
            routingRuleSetSourceDraft = ruleSet.source,
            routingRuleSetSourceTypeDraft = ruleSet.sourceType,
            routingRuleSetFormatDraft = ruleSet.format,
            routingRuleSetActionDraft = ruleSet.action,
            routingRuleSetUpdateHoursDraft = ruleSet.updateIntervalHours.toString(),
        )
    }

    fun closeRuleSetDialog() {
        _uiState.value = _uiState.value.copy(
            showRuleSetDialog = false,
            editingRuleSetId = "",
            routingRuleSetNameDraft = "",
            routingRuleSetSourceDraft = "",
            routingRuleSetSourceTypeDraft = RoutingRuleSetSourceType.REMOTE,
            routingRuleSetFormatDraft = RoutingRuleSetFormat.SOURCE,
            routingRuleSetActionDraft = RoutingRuleSetAction.DIRECT,
            routingRuleSetUpdateHoursDraft = "24",
        )
    }

    fun onRuleSetNameDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(routingRuleSetNameDraft = value.take(80))
    }

    fun onRuleSetSourceDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(routingRuleSetSourceDraft = value)
    }

    fun onRuleSetSourceTypeDraftChanged(value: RoutingRuleSetSourceType) {
        _uiState.value = _uiState.value.copy(routingRuleSetSourceTypeDraft = value)
    }

    fun onRuleSetFormatDraftChanged(value: RoutingRuleSetFormat) {
        _uiState.value = _uiState.value.copy(routingRuleSetFormatDraft = value)
    }

    fun onRuleSetActionDraftChanged(value: RoutingRuleSetAction) {
        _uiState.value = _uiState.value.copy(routingRuleSetActionDraft = value)
    }

    fun onRuleSetUpdateHoursDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(
            routingRuleSetUpdateHoursDraft = value.filter { it.isDigit() }.take(4),
        )
    }

    fun saveRuleSet() {
        val draft = buildRuleSetDraft()
        if (draft.isFailure) {
            postStatus(draft.exceptionOrNull()?.message ?: "Invalid rule-set")
            return
        }
        val saved = draft.getOrThrow()
        val wasEditing = _uiState.value.editingRuleSetId.isNotBlank()
        val existingId = _uiState.value.editingRuleSetId.takeIf { it.isNotBlank() } ?: saved.id
        val updated = _uiState.value.routingRuleSetsDraft
            .filterNot { it.id == existingId }
            .plus(saved.copy(id = existingId))
            .sortedBy { it.name.lowercase() }
        _uiState.value = _uiState.value.copy(
            routingRuleSetsDraft = updated,
        )
        closeRuleSetDialog()
        postStatus(
            if (wasEditing) {
                "Rule-set updated"
            } else {
                "Rule-set added"
            },
        )
    }

    fun deleteRuleSet(id: String) {
        val existing = _uiState.value.routingRuleSetsDraft
        if (existing.none { it.id == id }) return
        _uiState.value = _uiState.value.copy(
            routingRuleSetsDraft = existing.filterNot { it.id == id },
            showRuleSetDialog = if (_uiState.value.editingRuleSetId == id) false else _uiState.value.showRuleSetDialog,
            editingRuleSetId = if (_uiState.value.editingRuleSetId == id) "" else _uiState.value.editingRuleSetId,
        )
        postStatus("Rule-set removed")
    }

    fun showAddLocationDialog() {
        if (_uiState.value.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
            postStatus("Switch to Saved Locations to add locations manually")
            return
        }
        _uiState.value = _uiState.value.copy(
            showLocationDialog = true,
            locationDraft = "",
            editingLocationIndex = null,
        )
    }

    fun editLocation(index: Int) {
        val rawLink = _uiState.value.currentLocations.getOrNull(index) ?: return
        _uiState.value = _uiState.value.copy(
            showLocationDialog = true,
            locationDraft = runCatching { LocationConfigs.prettyStoredLocation(rawLink) }.getOrDefault(rawLink),
            editingLocationIndex = index,
        )
    }

    fun closeLocationDialog() {
        _uiState.value = _uiState.value.copy(
            showLocationDialog = false,
            locationDraft = "",
            editingLocationIndex = null,
        )
    }

    fun closeLocationMutationBlockedDialog() {
        _uiState.value = _uiState.value.copy(
            showLocationMutationBlockedDialog = false,
            locationMutationBlockedMessage = "",
        )
    }

    private fun showLocationMutationBlockedDialog(message: String) {
        _uiState.value = _uiState.value.copy(
            showLocationMutationBlockedDialog = true,
            locationMutationBlockedMessage = message,
        )
    }

    fun onLocationDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(locationDraft = value)
    }

    fun toggleProxyRoutingApp(packageName: String) {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        if (!nextProxy.add(packageName)) {
            nextProxy.remove(packageName)
        }
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun toggleDirectRoutingApp(packageName: String) {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.remove(packageName)
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun selectAllVisibleProxyApps() {
        val visiblePackages = filteredRoutingPackages()
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.addAll(visiblePackages)
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun clearAllVisibleProxyApps() {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(filteredRoutingPackages().toSet())
        _uiState.value = _uiState.value.copy(routingProxyPackagesDraft = nextProxy)
    }

    fun selectAllVisibleDirectApps() {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(filteredRoutingPackages().toSet())
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun clearAllVisibleDirectApps() {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(filteredRoutingPackages().toSet())
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = emptySet(),
        )
    }

    fun onVpnPermissionGranted() {
        _uiState.value = _uiState.value.copy(hasVpnPermission = true)
    }

    fun saveProfile() {
        val value = _uiState.value.profileDraft.trim()
        val mode = _uiState.value.profileSourceMode
        viewModelScope.launch {
            val result = saveProfileSource(value, mode)
            if (result.isFailure) return@launch
            _uiState.value = _uiState.value.copy(
                profileDraft = value,
                showAddSubscriptionEditor = false,
            )
        }
    }

    fun clearProfileSource() {
        _uiState.value = _uiState.value.copy(profileDraft = "")
    }

    fun refreshActiveSubscriptionCache() {
        viewModelScope.launch {
            if (_uiState.value.subscriptions.isEmpty()) {
                repository.updateStatus("No subscriptions saved yet")
                return@launch
            }
            setBusy(true)
            try {
                repository.updateStatus(
                    if (isAllSubscriptionsGroupActive(_uiState.value.activeSubscriptionId(), _uiState.value.subscriptions)) {
                        "Refreshing all subscriptions..."
                    } else {
                        "Refreshing active subscription..."
                    },
                )
                val result = repository.refreshActiveSubscriptionCache()
                repository.updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            if (isAllSubscriptionsGroupActive(_uiState.value.activeSubscriptionId(), _uiState.value.subscriptions)) {
                                formatRefreshSummaryMessage(
                                    refreshedCount = refresh.refreshedCount,
                                    failedSubscriptions = refresh.failedSubscriptions.map { it.displayName },
                                    totalCount = _uiState.value.subscriptions.size,
                                    defaultSuccess = "All subscriptions refreshed",
                                )
                            } else {
                                formatRefreshSummaryMessage(
                                    refreshedCount = refresh.refreshedCount,
                                    failedSubscriptions = refresh.failedSubscriptions.map { it.displayName },
                                    totalCount = 1,
                                    defaultSuccess = "Active subscription refreshed",
                                )
                            }
                        },
                        onFailure = { it.message ?: "Failed to refresh the active subscription" },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }

    fun refreshAllSubscriptionsCaches() {
        viewModelScope.launch {
            if (_uiState.value.subscriptions.isEmpty()) {
                repository.updateStatus("No subscriptions saved yet")
                return@launch
            }
            setBusy(true)
            try {
                repository.updateStatus("Refreshing all subscriptions...")
                val result = repository.refreshAllSubscriptionsCaches()
                repository.updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            formatRefreshSummaryMessage(
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptions = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = _uiState.value.subscriptions.size,
                                defaultSuccess = "Subscriptions refreshed: ${refresh.refreshedCount}/${_uiState.value.subscriptions.size}",
                            )
                        },
                        onFailure = { it.message ?: "Failed to refresh subscriptions" },
                    ),
                )
            } finally {
                setBusy(false)
            }
        }
    }

    fun handleIncomingSharedText(raw: String) {
        handleIncomingImportText(raw, ImportPreference.AUTO)
    }

    fun handleIncomingImportText(raw: String, preference: ImportPreference = ImportPreference.AUTO) {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return
        viewModelScope.launch {
            IncomingImportResolver.resolve(trimmed, preference).fold(
                onSuccess = { payload ->
                    when (payload) {
                        is IncomingImportPayload.Subscription -> {
                            repository.updateProfileSourceMode(ProfileSourceMode.SUBSCRIPTION)
                            navigateToScreen(AppScreen.PROFILE)
                            _uiState.value = _uiState.value.copy(
                                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                                profileDraft = payload.raw,
                                showAddSubscriptionEditor = true,
                            )
                            repository.updateStatus(
                                when (preference) {
                                    ImportPreference.SUBSCRIPTION -> "Subscription received. Review and save it on the Profile tab."
                                    else -> "Subscription link received. Review and save it on the Profile tab."
                                },
                            )
                        }
                        is IncomingImportPayload.Location -> {
                            repository.updateProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
                            navigateToScreen(AppScreen.LOCATIONS)
                            _uiState.value = _uiState.value.copy(
                                profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                                showLocationDialog = true,
                                locationDraft = payload.raw,
                                editingLocationIndex = null,
                            )
                            repository.updateStatus(
                                when (preference) {
                                    ImportPreference.LOCATION -> "Location config received. Review and save it on the Locations tab."
                                    else -> "Location config received. Review and save it on the Locations tab."
                                },
                            )
                        }
                        is IncomingImportPayload.RoutingRules -> {
                            navigateToScreen(AppScreen.ROUTING_RULES)
                            importRoutingRules(payload.raw)
                        }
                    }
                },
                onFailure = { error ->
                    repository.updateStatus(
                        error.message ?: "Shared text is not a supported import payload",
                    )
                },
            )
        }
    }

    fun useProfileHistoryEntry(subscriptionId: String) {
        val normalized = subscriptionId.trim()
        val selectedUrl = _uiState.value.subscriptions
            .firstOrNull { it.id == normalized }
            ?.url
            .orEmpty()
        _uiState.value = _uiState.value.copy(
            profileDraft = if (normalized == ALL_SUBSCRIPTIONS_ID) "" else selectedUrl,
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            showAddSubscriptionEditor = false,
        )
        viewModelScope.launch {
            repository.selectActiveSubscription(normalized)
            repository.updateStatus(
                if (normalized == ALL_SUBSCRIPTIONS_ID) {
                    "All subscriptions selected"
                } else {
                    "Subscription selected"
                },
            )
        }
    }

    fun deleteProfileHistoryEntry(source: String) {
        viewModelScope.launch {
            repository.deleteProfileHistoryEntry(source)
            if (_uiState.value.profileHistoryRenameSource == source) {
                closeProfileHistoryRenameDialog()
            }
            repository.updateStatus("History entry deleted")
        }
    }

    fun saveProfileHistoryRename() {
        val source = _uiState.value.profileHistoryRenameSource.trim()
        if (source.isBlank()) {
            closeProfileHistoryRenameDialog()
            return
        }
        val normalizedName = _uiState.value.profileHistoryRenameDraft.trim()
        viewModelScope.launch {
            repository.updateProfileHistoryName(source, normalizedName)
            repository.updateStatus(
                if (normalizedName.isBlank()) {
                    "Subscription name reset"
                } else {
                    "Subscription name saved"
                },
            )
            closeProfileHistoryRenameDialog()
        }
    }

    fun saveSubscriptionRefreshPolicy() {
        val policy = _uiState.value.subscriptionRefreshPolicyDraft
        val customHours = _uiState.value.subscriptionRefreshCustomHoursDraft
            .replace(',', '.')
            .toDoubleOrNull()
        viewModelScope.launch {
            if (policy == SubscriptionRefreshPolicy.CUSTOM && customHours == null) {
                repository.updateStatus("Enter a valid custom refresh interval in hours")
                return@launch
            }
            if (policy == SubscriptionRefreshPolicy.CUSTOM &&
                customHours != null &&
                customHours * 60.0 < MIN_SUBSCRIPTION_REFRESH_MINUTES
            ) {
                repository.updateStatus(
                    "Custom refresh interval must be at least $MIN_SUBSCRIPTION_REFRESH_MINUTES minutes",
                )
                return@launch
            }
            val resolvedHours = when (policy) {
                SubscriptionRefreshPolicy.OFF ->
                    normalizeSubscriptionRefreshCustomHours(_uiState.value.subscriptionRefreshCustomHours)
                SubscriptionRefreshPolicy.EVERY_HOUR -> 1.0
                SubscriptionRefreshPolicy.CUSTOM ->
                    normalizeSubscriptionRefreshCustomHours(
                        customHours ?: _uiState.value.subscriptionRefreshCustomHours,
                    )
            }
            repository.updateSubscriptionRefreshPolicy(
                policy = policy,
                customHours = resolvedHours,
                findBestAfterRefresh = _uiState.value.findBestAfterSubscriptionRefreshDraft,
            )
            repository.updateStatus(
                "Subscription auto-refresh set to ${policy.displayValue(resolvedHours).lowercase()}",
            )
            _uiState.value = _uiState.value.copy(showRefreshPolicyDialog = false)
        }
    }

    private fun sanitizeDecimalInput(value: String): String {
        val normalized = value.replace(',', '.')
        val builder = StringBuilder()
        var dotSeen = false
        normalized.forEach { char ->
            when {
                char.isDigit() -> builder.append(char)
                char == '.' && !dotSeen -> {
                    if (builder.isEmpty()) {
                        builder.append('0')
                    }
                    builder.append('.')
                    dotSeen = true
                }
            }
        }
        return builder.toString()
    }

    fun saveValidationSettings() {
        viewModelScope.launch {
            val batchSize = _uiState.value.validationBatchSizeDraft.toIntOrNull()
                ?: BenchmarkValidationSettings.DEFAULT_BATCH_SIZE
            val retryCount = _uiState.value.validationRetryCountDraft.toIntOrNull()
                ?: BenchmarkValidationSettings.DEFAULT_RETRY_COUNT
            val settings = BenchmarkValidationSettings(
                primaryUrl = _uiState.value.validationPrimaryUrlDraft,
                secondaryUrl = _uiState.value.validationSecondaryUrlDraft,
                batchSize = batchSize,
                retryCount = retryCount,
            ).normalized()
            repository.updateValidationSettings(settings)
            repository.updateStatus(
                "Validation settings saved: ${settings.displaySummary()}",
            )
            _uiState.value = _uiState.value.copy(showValidationSettingsDialog = false)
        }
    }

    fun saveLocation() {
        val rawLink = _uiState.value.locationDraft.trim()
        viewModelScope.launch {
            if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                _uiState.value.editingLocationIndex != null
            ) {
                showLocationMutationBlockedDialog(
                    "Subscription locations are read-only. Switch to Saved Locations to save edits.",
                )
                return@launch
            }
            val parsed = runCatching { LocationConfigs.parseLocationInput(rawLink) }
            if (parsed.isFailure) {
                repository.updateStatus(parsed.exceptionOrNull()?.message ?: "Invalid location config")
                return@launch
            }

            val nextLocations = _uiState.value.currentLocations.toMutableList()
            val editIndex = _uiState.value.editingLocationIndex
            val replacedRawLink = editIndex?.let { nextLocations.getOrNull(it) }
            val normalized = LocationConfigs.encodeStoredLocation(parsed.getOrThrow())
            val duplicateIndex = nextLocations.indexOf(normalized)
            val previousState = repository.snapshot()
            if (editIndex == null && duplicateIndex != -1) {
                repository.updateStatus("Location already saved: ${parsed.getOrThrow().remarks}")
                return@launch
            }
            val mergedWithExisting = editIndex != null && duplicateIndex != -1 && duplicateIndex != editIndex
            if (editIndex == null) {
                nextLocations.add(normalized)
            } else if (editIndex in nextLocations.indices) {
                nextLocations[editIndex] = normalized
            }
            repository.updateCurrentLocations(nextLocations)
            if (replacedRawLink != null && replacedRawLink == selectedLocationReference()) {
                val selectionResult = repository.selectionFromRawLink(
                    rawLink = normalized,
                    detail = "Selected location updated",
                )
                if (selectionResult.isFailure) {
                    repository.restoreSnapshot(previousState)
                    repository.updateStatus(
                        selectionResult.exceptionOrNull()?.message
                            ?: "Failed to apply updated selected location",
                    )
                    return@launch
                }
                val applyResult = applyAndPersistSelection(
                    selection = selectionResult.getOrThrow(),
                    statusMessage = "Applying updated selected location...",
                )
                if (!applyResult.isSuccess) {
                    val message = selectionCommitFailureMessage(
                        result = applyResult,
                        applyFailureFallback = "Failed to apply updated selected location",
                        persistFailureWithoutApplyFallback = "Failed to save the updated selected location",
                        persistFailureAfterApplyFallback = "Updated selected location applied, but failed to save it",
                    )
                    val resolvedMessage = if (applyResult.requiresLiveRollback) {
                        rollbackSelectionChange(previousState, message)
                    } else {
                        repository.restoreSnapshot(previousState)
                        message
                    }
                    repository.updateStatus(resolvedMessage)
                    return@launch
                }
            }
            repository.updateStatus(
                if (editIndex == null) {
                    "Location added: ${parsed.getOrThrow().remarks}"
                } else if (mergedWithExisting) {
                    "Location updated and merged: ${parsed.getOrThrow().remarks}"
                } else {
                    "Location updated: ${parsed.getOrThrow().remarks}"
                },
            )
            closeLocationDialog()
        }
    }

    fun deleteLocation(index: Int) {
        if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            showLocationMutationBlockedDialog(
                "Subscription locations are read-only. Switch to Saved Locations to delete them.",
            )
            return
        }
        val nextLocations = _uiState.value.currentLocations.toMutableList()
        val removed = nextLocations.getOrNull(index) ?: return
        nextLocations.removeAt(index)
        viewModelScope.launch {
            val previousState = repository.snapshot()
            val update = repository.updateCurrentLocations(nextLocations)
            val remarks = runCatching { LocationConfigs.decodeStoredLocation(removed).remarks }.getOrDefault("Location")
            val removedSelected = update.selectedMissing
            if (removedSelected && _uiState.value.isVpnRunning) {
                val stopResult = vpnManager.stop()
                repository.updateStatus(
                    stopResult.fold(
                        onSuccess = { "Selected location removed. ${stoppedConnectionLabel()}: $remarks" },
                        onFailure = {
                            repository.restoreSnapshot(previousState)
                            it.message ?: "Location removal rolled back because the ${connectionNoun()} could not be stopped"
                        },
                    ),
                )
            } else {
                repository.updateStatus(
                    if (removedSelected) {
                        "Selected location removed: $remarks"
                    } else {
                        "Location removed: $remarks"
                    },
                )
            }
        }
    }

    fun benchmarkLocation(index: Int) {
        val rawLink = _uiState.value.currentLocations.getOrNull(index) ?: return
        benchmarkLocationStored(rawLink)
    }

    fun benchmarkSelectedLocationFromStats() {
        val rawLink = selectedLocationReference().ifBlank {
            _uiState.value.currentLocations.firstOrNull {
                it == selectedLocationReference()
            }.orEmpty()
        }
        if (rawLink.isBlank()) {
            viewModelScope.launch {
                repository.updateStatus("Select a location first")
            }
            return
        }
        benchmarkLocationStored(rawLink)
    }

    fun selectLocation(index: Int) {
        val rawLink = _uiState.value.currentLocations.getOrNull(index) ?: return
        viewModelScope.launch {
            setBusy(true)
            val isSelected = rawLink == selectedLocationReference()
            val previousState = repository.snapshot()
            val result = if (isSelected) {
                Result.success("Selected location unchanged")
            } else {
                val selectionResult = repository.selectionFromRawLink(
                    rawLink = rawLink,
                    detail = "Selected location manually",
                )
                if (selectionResult.isFailure) {
                    Result.failure(selectionResult.exceptionOrNull() ?: IllegalStateException("Failed to select location"))
                } else {
                    val applyResult = applyAndPersistSelection(
                        selection = selectionResult.getOrThrow(),
                        statusMessage = "Applying selected location...",
                    )
                    if (!applyResult.isSuccess) {
                        val message = selectionCommitFailureMessage(
                            result = applyResult,
                            applyFailureFallback = "Failed to apply selected location",
                            persistFailureWithoutApplyFallback = "Failed to save selected location",
                            persistFailureAfterApplyFallback = "Selected location applied, but failed to save it",
                        )
                        val resolvedMessage = if (applyResult.requiresLiveRollback) {
                            rollbackSelectionChange(previousState, message)
                        } else {
                            if (applyResult.shouldRestoreSnapshot) {
                                repository.restoreSnapshot(previousState)
                            }
                            message
                        }
                        Result.failure(IllegalStateException(resolvedMessage))
                    } else {
                        Result.success("Selected location set")
                    }
                }
            }
            repository.updateStatus(
                if (result.isSuccess) {
                    val remarks = runCatching { LocationConfigs.decodeStoredLocation(rawLink).remarks }
                        .getOrDefault("Location")
                    if (isSelected) {
                        "Selected location unchanged: $remarks"
                    } else {
                        "Selected location set: $remarks"
                    }
                } else {
                    result.exceptionOrNull()?.message ?: "Failed to select location"
                },
            )
            setBusy(false)
        }
    }

    fun saveDns() {
        val dns = _uiState.value.customDnsDraft.trim()
        val enabled = _uiState.value.useCustomDnsDraft && dns.isNotBlank()
        viewModelScope.launch {
            repository.updateCustomDns(dns = dns, enabled = enabled)
            repository.updateStatus(
                if (enabled) "Custom DNS saved" else "Custom DNS disabled",
            )
            _uiState.value = _uiState.value.copy(showDnsDialog = false)
        }
    }

    fun saveRoutingRules() {
        val rules = editedRoutingRules()
        viewModelScope.launch {
            setBusy(true)
            val result = repository.updateRoutingRules(rules)
            repository.updateStatus(
                result.fold(
                    onSuccess = {
                        if (_uiState.value.isVpnRunning) {
                            "Routing rules saved. Restart ${connectionNoun()} to apply"
                        } else {
                            "Routing rules saved"
                        }
                    },
                    onFailure = { it.message ?: "Failed to save routing rules" },
                ),
            )
            if (result.isSuccess) {
                navigateBack()
            }
            setBusy(false)
        }
    }

    fun buildRoutingRulesExport(): RoutingRulesExportDocument {
        return RoutingRulesTransfer.export(editedRoutingRules())
    }

    fun buildLocationsExport(): LocationsExportDocument {
        return LocationConfigs.export(_uiState.value.currentLocations)
    }

    fun importLocations(raw: String) {
        viewModelScope.launch {
            if (_uiState.value.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
                repository.updateStatus("Switch to Saved Locations to import locations")
                return@launch
            }
            setBusy(true)
            val parsed = runCatching { LocationConfigs.import(raw) }
            if (parsed.isFailure) {
                repository.updateStatus(parsed.exceptionOrNull()?.message ?: "Failed to import locations")
                setBusy(false)
                return@launch
            }
            val previousState = repository.snapshot()
            val update = repository.updateCurrentLocations(parsed.getOrThrow())
            val removedSelected = update.selectedMissing &&
                _uiState.value.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS
            if (removedSelected && _uiState.value.isVpnRunning) {
                val stopResult = vpnManager.stop()
                repository.updateStatus(
                    stopResult.fold(
                        onSuccess = { "Locations imported. Selected location is no longer available, ${stoppedConnectionLabel().lowercase()}" },
                        onFailure = {
                            repository.restoreSnapshot(previousState)
                            it.message ?: "Locations import rolled back because the ${connectionNoun()} could not be stopped"
                        },
                    ),
                )
            } else {
                repository.updateStatus(
                    if (removedSelected) {
                        "Locations imported. Selected location is no longer available"
                    } else {
                        "Locations imported"
                    },
                )
            }
            setBusy(false)
        }
    }

    fun importRoutingRules(raw: String) {
        viewModelScope.launch {
            setBusy(true)
            val parsed = runCatching { RoutingRulesTransfer.import(raw) }
            if (parsed.isFailure) {
                repository.updateStatus(parsed.exceptionOrNull()?.message ?: "Failed to import routing rules")
                setBusy(false)
                return@launch
            }

            val rules = sanitizeRoutingRules(parsed.getOrThrow())
            val result = repository.updateRoutingRules(rules)
            repository.updateStatus(
                result.fold(
                    onSuccess = {
                        _uiState.value = _uiState.value.copy(
                            routingIgnoreRulesDraft = rules.ignoreRules,
                            routingProxyPackagesDraft = rules.proxyPackages.toSet(),
                            routingBypassPackagesDraft = emptySet(),
                            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
                            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
                            routingRuleSetsDraft = rules.ruleSets,
                            showRuleSetDialog = false,
                            editingRuleSetId = "",
                        )
                        if (_uiState.value.isVpnRunning) {
                            "Routing rules imported. Restart ${connectionNoun()} to apply"
                        } else {
                            "Routing rules imported"
                        }
                    },
                    onFailure = { it.message ?: "Failed to import routing rules" },
                ),
            )
            setBusy(false)
        }
    }

    fun postStatus(message: String) {
        viewModelScope.launch {
            repository.updateStatus(message)
        }
    }

    fun cancelActiveOperation() {
        activeBusyJob?.cancel(CancellationException("Cancelled by user"))
    }

    fun refresh() {
        launchTrackedBusyOperation {
            if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                currentSubscriptionSearchTargets().isEmpty()
            ) {
                repository.updateStatus("Set a remote source first")
                return@launchTrackedBusyOperation
            }
            if (_uiState.value.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS &&
                _uiState.value.currentLocations.isEmpty()
            ) {
                repository.updateStatus("Add at least one saved location first")
                return@launchTrackedBusyOperation
            }
            setBusy(true)
            _uiState.value = _uiState.value.copy(isRefreshing = true)
            val previousState = repository.snapshot()
            var startAttempted = false
            try {
                repository.updateStatus(
                    if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                        "Finding the best location from the subscription..."
                    } else {
                        "Finding the best location from saved locations..."
                    },
                )
                val result = findBestProfileWithRetries()
                val message = result.fold(
                    onSuccess = { selection ->
                        startAttempted = true
                        val applyResult = startAndPersistSelection(
                            selection = selection,
                            statusMessage = bestSelectionStartMessage(),
                        )
                        if (applyResult.isSuccess) {
                            appendLatencyHistory(selection.benchmark)
                            "Best location selected and ${startedConnectionLabel().lowercase()}: ${selection.profile.remarks}"
                        } else if (applyResult.requiresLiveRollback) {
                            rollbackSelectionChange(
                                previousState = previousState,
                                baseMessage = selectionCommitFailureMessage(
                                    result = applyResult,
                                    applyFailureFallback = "Failed to start ${connectionNoun()} with the best location",
                                    persistFailureWithoutApplyFallback = "Failed to save the best location",
                                    persistFailureAfterApplyFallback = "Best location ${connectionNoun()} started, but failed to save it",
                                ),
                            )
                        } else {
                            if (applyResult.shouldRestoreSnapshot) {
                                repository.restoreSnapshot(previousState)
                            }
                            selectionCommitFailureMessage(
                                result = applyResult,
                                applyFailureFallback = "Failed to start ${connectionNoun()} with the best location",
                                persistFailureWithoutApplyFallback = "Failed to save the best location",
                                persistFailureAfterApplyFallback = "Best location ${connectionNoun()} started, but failed to save it",
                            )
                        }
                    },
                    onFailure = { error ->
                        error.message ?: "Location search failed"
                    },
                )
                repository.updateStatus(message)
            } catch (_: CancellationException) {
                withContext(NonCancellable) {
                    val message = when {
                        startAttempted && previousState.isVpnRunning ->
                            rollbackSelectionChange(previousState, "Location search cancelled.")
                        startAttempted -> {
                            val stopResult = vpnManager.stop()
                            stopResult.fold(
                                onSuccess = {
                                    repository.restoreSnapshot(previousState)
                                    "Location search cancelled"
                                },
                                onFailure = { "Location search cancelled. ${it.message ?: "Failed to stop ${connectionNoun()}."}" },
                            )
                        }
                        else -> "Location search cancelled"
                    }
                    repository.updateStatus(message)
                }
            } finally {
                _uiState.value = _uiState.value.copy(isRefreshing = false)
                setBusy(false)
            }
        }
    }

    fun toggleVpn() {
        launchTrackedBusyOperation {
            if (_uiState.value.isVpnRunning) {
                setBusy(true)
                try {
                    val result = vpnManager.stop()
                    repository.updateStatus(
                        result.fold(
                            onSuccess = { stoppedConnectionLabel() },
                            onFailure = { it.message ?: "Failed to stop ${connectionNoun()}" },
                        ),
                    )
                } catch (_: CancellationException) {
                    withContext(NonCancellable) {
                        repository.updateStatus("${connectionDisplayName()} stop cancelled")
                    }
                } finally {
                    setBusy(false)
                }
                return@launchTrackedBusyOperation
            }

            if (_uiState.value.appMode == AppMode.VPN && !_uiState.value.hasVpnPermission) {
                repository.updateStatus("Grant VPN permission and try again")
                return@launchTrackedBusyOperation
            }

            setBusy(true)
            val previousState = repository.snapshot()
            var startAttempted = false
            try {
                repository.updateStatus("Preparing ${connectionNoun()}")

                val selection = repository.ensureSelection()
                if (selection.isFailure) {
                    repository.updateStatus(selection.exceptionOrNull()?.message ?: "Could not prepare ${connectionNoun()}")
                    return@launchTrackedBusyOperation
                }

                startAttempted = true
                val applyResult = startAndPersistSelection(
                    selection = selection.getOrThrow(),
                    statusMessage = startingConnectionLabel(),
                )
                val message = if (applyResult.isSuccess) {
                    startedConnectionLabel()
                } else {
                    selectionCommitFailureMessage(
                        result = applyResult,
                        applyFailureFallback = "Failed to start ${connectionNoun()}",
                        persistFailureWithoutApplyFallback = "Failed to save the selected location",
                        persistFailureAfterApplyFallback = "${connectionDisplayName()} started, but failed to save the selected location",
                    ).let { failureMessage ->
                        if (applyResult.requiresLiveRollback) {
                            rollbackStartedVpnAfterPersistFailure(
                                previousState = previousState,
                                applyResult.error ?: IllegalStateException(failureMessage),
                            )
                        } else if (applyResult.shouldRestoreSnapshot) {
                            repository.restoreSnapshot(previousState)
                            failureMessage
                        } else {
                            failureMessage
                        }
                    }
                }
                repository.updateStatus(message)
            } catch (_: CancellationException) {
                withContext(NonCancellable) {
                    if (startAttempted) {
                        val stopResult = vpnManager.stop()
                        repository.updateStatus(
                            stopResult.fold(
                                onSuccess = {
                                    repository.restoreSnapshot(previousState)
                                    "${connectionDisplayName()} start cancelled"
                                },
                                onFailure = { "${connectionDisplayName()} start cancelled. ${it.message ?: "Failed to stop ${connectionNoun()}."}" },
                            ),
                        )
                    } else {
                        repository.updateStatus("${connectionDisplayName()} start cancelled")
                    }
                }
            } finally {
                setBusy(false)
            }
        }
    }

    fun exportDiagnostics() {
        viewModelScope.launch {
            setBusy(true)
            val result = diagnosticsExporter.exportAndShare()
            repository.updateStatus(
                result.fold(
                    onSuccess = { "Diagnostics export opened" },
                    onFailure = { it.message ?: "Diagnostics export failed" },
                ),
            )
            setBusy(false)
        }
    }

    private fun ensureInstalledAppsLoaded() {
        if (_uiState.value.installedAppsLoaded || _uiState.value.installedAppsLoading) {
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(installedAppsLoading = true)
            runCatching { installedAppsCatalog.load() }
                .onSuccess { apps ->
                    _uiState.value = _uiState.value.copy(
                        installedApps = apps,
                        installedAppsLoaded = true,
                        installedAppsLoading = false,
                    )
                }
                .onFailure { error ->
                    _uiState.value = _uiState.value.copy(installedAppsLoading = false)
                    repository.updateStatus(error.message ?: "Failed to load apps")
                }
        }
    }

    private fun setBusy(value: Boolean) {
        _uiState.value = _uiState.value.copy(isBusy = value)
    }

    private suspend fun saveProfileSource(
        value: String,
        mode: ProfileSourceMode,
    ): Result<Unit> {
        if (mode == ProfileSourceMode.SUBSCRIPTION && value.isBlank()) {
            repository.updateStatus("Paste a subscription URL or choose one from the list")
            return Result.failure(IllegalStateException("Subscription URL is empty"))
        }
        if (mode == ProfileSourceMode.SUBSCRIPTION && value.isNotBlank()) {
            val validation = RemoteSourceResolver.validateProfileSource(value)
            if (validation.isFailure) {
                repository.updateStatus(
                    validation.exceptionOrNull()?.message ?: "Invalid remote source",
                )
                return Result.failure(
                    validation.exceptionOrNull() ?: IllegalStateException("Invalid remote source"),
                )
            }
        }
        repository.updateProfileSource(value, mode)
        repository.updateStatus(
            if (mode == ProfileSourceMode.SUBSCRIPTION) {
                "Subscription saved"
            } else {
                "Profile source set to saved locations"
            },
        )
        return Result.success(Unit)
    }

    private fun MainUiState.activeSubscriptionId(): String = activeSubscriptionId

    private fun currentSubscriptionSearchTargets(): List<SubscriptionSource> {
        val state = _uiState.value
        return if (isAllSubscriptionsGroupActive(state.activeSubscriptionId(), state.subscriptions)) {
            state.subscriptions.filter { it.url.isNotBlank() }
        } else {
            state.subscriptions.filter { it.id == state.activeSubscriptionId() && it.url.isNotBlank() }
        }
    }

    private suspend fun reapplyVpnIfRunning(
        selection: com.kardinal.vpncontrol.model.ProfileSelection,
        statusMessage: String,
    ): Result<Unit> {
        if (!_uiState.value.isVpnRunning) {
            return Result.success(Unit)
        }

        _uiState.value = _uiState.value.copy(isStartingVpn = true)
        return try {
            repository.updateStatus(statusMessage)
            vpnManager.start(selection)
        } finally {
            _uiState.value = _uiState.value.copy(isStartingVpn = false)
        }
    }

    private suspend fun startAndPersistSelection(
        selection: com.kardinal.vpncontrol.model.ProfileSelection,
        statusMessage: String,
    ): SelectionCommitResult {
        _uiState.value = _uiState.value.copy(isStartingVpn = true)
        return try {
            repository.updateStatus(statusMessage)
            val startResult = vpnManager.start(selection)
            if (startResult.isFailure) {
                return SelectionCommitResult(
                    stage = SelectionCommitStage.APPLY_FAILED,
                    error = startResult.exceptionOrNull(),
                )
            }
            val persistResult = runCatching {
                repository.persistSelection(selection)
            }
            if (persistResult.isFailure) {
                return SelectionCommitResult(
                    stage = SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY,
                    error = persistResult.exceptionOrNull(),
                )
            }
            SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
        } finally {
            _uiState.value = _uiState.value.copy(isStartingVpn = false)
        }
    }

    private suspend fun applyAndPersistSelection(
        selection: com.kardinal.vpncontrol.model.ProfileSelection,
        statusMessage: String,
    ): SelectionCommitResult {
        val vpnWasRunning = _uiState.value.isVpnRunning
        val applyResult = reapplyVpnIfRunning(
            selection = selection,
            statusMessage = statusMessage,
        )
        if (applyResult.isFailure) {
            return SelectionCommitResult(
                stage = SelectionCommitStage.APPLY_FAILED,
                error = applyResult.exceptionOrNull(),
            )
        }
        val persistResult = runCatching {
            repository.persistSelection(selection)
        }
        if (persistResult.isFailure) {
            return SelectionCommitResult(
                stage = if (vpnWasRunning) {
                    SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY
                } else {
                    SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY
                },
                error = persistResult.exceptionOrNull(),
            )
        }
        return SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
    }

    private suspend fun findBestProfileWithRetries(): Result<com.kardinal.vpncontrol.model.ProfileSelection> {
        val retryCount = _uiState.value.validationSettings.retryCount.coerceAtLeast(0)
        var lastFailure: Throwable? = null
        repeat(retryCount + 1) { attempt ->
            if (attempt > 0) {
                repository.updateStatus(
                    "Retrying best location search (${attempt + 1}/${retryCount + 1})...",
                )
                delay(750)
            }
            val result = repository.refreshBestProfile()
            if (result.isSuccess) {
                return result
            }
            lastFailure = result.exceptionOrNull()
        }
        return Result.failure(
            lastFailure ?: IllegalStateException("Location search failed"),
        )
    }

    private fun selectedLocationReference(): String {
        return LocationConfigs.selectedStoredReference(
            selectedProfileJson = _uiState.value.selectedProfileJson,
            selectedProfileRawLink = _uiState.value.selectedProfileRawLink,
        )
    }

    private fun benchmarkLocationStored(rawLink: String) {
        launchTrackedBusyOperation {
            setBusy(true)
            _uiState.value = _uiState.value.copy(isRefreshing = true)
            try {
                val remarks = runCatching { LocationConfigs.decodeStoredLocation(rawLink).remarks }
                    .getOrDefault("Location")
                repository.updateStatus("Checking $remarks...")
                val result = repository.benchmarkLocation(rawLink)
                result.onSuccess { benchmark ->
                    appendLatencyHistory(benchmark)
                }
                repository.updateStatus(
                    result.fold(
                        onSuccess = { benchmark -> "Location checked: ${benchmark.profile.remarks}" },
                        onFailure = { it.message ?: "Location check failed" },
                    ),
                )
            } catch (_: CancellationException) {
                withContext(NonCancellable) {
                    repository.updateStatus("Location check cancelled")
                }
            } finally {
                _uiState.value = _uiState.value.copy(isRefreshing = false)
                setBusy(false)
            }
        }
    }

    private suspend fun appendLatencyHistory(benchmark: com.kardinal.vpncontrol.model.ProfileBenchmark) {
        repository.appendLatencyHistory(
            LatencyHistoryEntry(
                id = UUID.randomUUID().toString(),
                profileName = benchmark.profile.remarks,
                detail = benchmark.detail,
                primaryStatus = benchmark.primaryStatus,
                secondaryStatus = benchmark.secondaryStatus,
                primaryTotalMs = benchmark.primaryTotal,
                secondaryTotalMs = benchmark.secondaryTotal,
                createdAtEpochMillis = System.currentTimeMillis(),
            ),
        )
    }

    private fun selectionCommitFailureMessage(
        result: SelectionCommitResult,
        applyFailureFallback: String,
        persistFailureWithoutApplyFallback: String,
        persistFailureAfterApplyFallback: String,
    ): String {
        return when (result.stage) {
            SelectionCommitStage.SUCCESS -> ""
            SelectionCommitStage.APPLY_FAILED ->
                result.error?.message ?: applyFailureFallback
            SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY ->
                result.error?.message ?: persistFailureWithoutApplyFallback
            SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY ->
                result.error?.message ?: persistFailureAfterApplyFallback
        }
    }

    private suspend fun rollbackSelectionChange(
        previousState: PersistedState,
        baseMessage: String,
    ): String {
        val restoredSelection = repository.rehydrateSelection(previousState)
        if (restoredSelection.isSuccess) {
            val restartResult = vpnManager.start(restoredSelection.getOrThrow())
            return restartResult.fold(
                onSuccess = {
                    repository.restoreSnapshot(previousState, restoreRuntimeArtifacts = false)
                    "$baseMessage Previous ${connectionNoun()} location restored."
                },
                onFailure = { restartError ->
                    val stopResult = vpnManager.stop()
                    stopResult.fold(
                        onSuccess = {
                            repository.restoreSnapshot(previousState)
                            "$baseMessage ${restartError.message ?: "Failed to restore the previous ${connectionNoun()} location."} " +
                                "${stoppedConnectionLabel()} to keep state consistent."
                        },
                        onFailure = { stopError ->
                            "$baseMessage ${restartError.message ?: "Failed to restore the previous ${connectionNoun()} location."} " +
                                "${stopError.message ?: "Failed to stop the current ${connectionNoun()} session."}"
                        },
                    )
                },
            )
        }

        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                repository.restoreSnapshot(previousState)
                "$baseMessage ${stoppedConnectionLabel()} to keep state consistent."
            },
            onFailure = { error ->
                "$baseMessage ${error.message ?: "Failed to restore the previous ${connectionNoun()} session."}"
            },
        )
    }

    private suspend fun rollbackStartedVpnAfterPersistFailure(
        previousState: PersistedState,
        error: Throwable,
    ): String {
        val baseMessage = error.message ?: "Failed to save the selected location"
        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                repository.restoreSnapshot(previousState)
                "$baseMessage ${connectionDisplayName()} was stopped to keep state consistent."
            },
            onFailure = { stopError ->
                "$baseMessage ${stopError.message ?: "${connectionDisplayName()} is still running and may not match the saved selection."}"
            },
        )
    }

    private fun connectionNoun(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "VPN"
            AppMode.PROXY_ONLY -> "proxy"
        }
    }

    private fun connectionDisplayName(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "VPN"
            AppMode.PROXY_ONLY -> "Proxy"
        }
    }

    private fun formatRefreshSummaryMessage(
        refreshedCount: Int,
        failedSubscriptions: List<String>,
        totalCount: Int,
        defaultSuccess: String,
    ): String {
        if (failedSubscriptions.isEmpty()) {
            return defaultSuccess
        }
        val distinctFailures = failedSubscriptions.distinct()
        val failedLabel = distinctFailures
            .take(2)
            .joinToString(", ")
        val overflow = (distinctFailures.size - 2).coerceAtLeast(0)
        val failedSuffix = if (overflow > 0) {
            "$failedLabel +$overflow more"
        } else {
            failedLabel
        }
        return "Subscriptions refreshed: $refreshedCount/$totalCount. Failed: $failedSuffix"
    }

    private fun startingConnectionLabel(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "Starting VPN..."
            AppMode.PROXY_ONLY -> "Starting local proxy..."
        }
    }

    private fun startedConnectionLabel(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "VPN started"
            AppMode.PROXY_ONLY -> "Proxy started"
        }
    }

    private fun stoppedConnectionLabel(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "VPN stopped"
            AppMode.PROXY_ONLY -> "Proxy stopped"
        }
    }

    private fun bestSelectionStartMessage(): String {
        return when (_uiState.value.appMode) {
            AppMode.VPN -> "Starting VPN with the best location..."
            AppMode.PROXY_ONLY -> "Starting local proxy with the best location..."
        }
    }

    private fun launchTrackedBusyOperation(block: suspend () -> Unit) {
        if (activeBusyJob?.isActive == true) return
        lateinit var job: Job
        job = viewModelScope.launch {
            try {
                block()
            } finally {
                if (activeBusyJob === job) {
                    activeBusyJob = null
                }
            }
        }
        activeBusyJob = job
    }

    private fun navigateToScreen(screen: AppScreen) {
        val current = _uiState.value.currentScreen
        if (current == screen) return
        _uiState.value = _uiState.value.copy(
            currentScreen = screen,
            screenHistory = _uiState.value.screenHistory + current,
            profileDraft = if (screen == AppScreen.PROFILE) _uiState.value.profileUrl else _uiState.value.profileDraft,
            showAddSubscriptionEditor = if (screen == AppScreen.PROFILE) false else _uiState.value.showAddSubscriptionEditor,
        )
    }

    private fun editedRoutingRules(): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(_uiState.value.routingProxyPackagesDraft)
        return RoutingRules(
            ignoreRules = _uiState.value.routingIgnoreRulesDraft,
            proxyPackages = proxyPackages,
            bypassPackages = emptyList(),
            nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(_uiState.value.routingNationalDomainsDraft),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(_uiState.value.routingDirectDomainsDraft),
            ruleSets = sanitizeRuleSets(_uiState.value.routingRuleSetsDraft),
        )
    }

    private fun buildRuleSetDraft(): Result<RoutingRuleSet> = runCatching {
        val name = _uiState.value.routingRuleSetNameDraft.trim()
        require(name.isNotBlank()) { "Rule-set name is required" }
        val sourceType = _uiState.value.routingRuleSetSourceTypeDraft
        val source = _uiState.value.routingRuleSetSourceDraft.trim()
        require(source.isNotBlank()) {
            when (sourceType) {
                RoutingRuleSetSourceType.INLINE -> "Inline rule-set content is required"
                RoutingRuleSetSourceType.REMOTE -> "Remote rule-set URL is required"
            }
        }
        when (sourceType) {
            RoutingRuleSetSourceType.INLINE -> requireInlineRuleSet(source)
            RoutingRuleSetSourceType.REMOTE -> requireRemoteRuleSetUrl(source)
        }
        RoutingRuleSet(
            id = _uiState.value.editingRuleSetId.takeIf { it.isNotBlank() } ?: UUID.randomUUID().toString(),
            name = name,
            sourceType = sourceType,
            format = _uiState.value.routingRuleSetFormatDraft,
            action = _uiState.value.routingRuleSetActionDraft,
            source = if (sourceType == RoutingRuleSetSourceType.REMOTE) {
                normalizeHttpsUrl(source)
            } else {
                source
            },
            updateIntervalHours = _uiState.value.routingRuleSetUpdateHoursDraft.toIntOrNull()?.coerceAtLeast(1) ?: 24,
        ).normalized()
    }

    private fun sanitizeRuleSets(ruleSets: List<RoutingRuleSet>): List<RoutingRuleSet> {
        return ruleSets
            .mapNotNull { ruleSet ->
                runCatching {
                    when (ruleSet.sourceType) {
                        RoutingRuleSetSourceType.INLINE -> requireInlineRuleSet(ruleSet.source)
                        RoutingRuleSetSourceType.REMOTE -> requireRemoteRuleSetUrl(ruleSet.source)
                    }
                    ruleSet.normalized().copy(
                        source = if (ruleSet.sourceType == RoutingRuleSetSourceType.REMOTE) {
                            normalizeHttpsUrl(ruleSet.source)
                        } else {
                            ruleSet.source.trim()
                        },
                    )
                }.getOrNull()
            }
            .distinctBy { it.id }
            .sortedBy { it.name.lowercase() }
    }

    private fun requireRemoteRuleSetUrl(raw: String) {
        val normalized = normalizeHttpsUrl(raw)
        val uri = URI(normalized)
        require(uri.scheme?.lowercase() == "https" && !uri.host.isNullOrBlank()) {
            "Remote rule-set URL must be a valid HTTPS URL"
        }
    }

    private fun normalizeHttpsUrl(raw: String): String {
        val trimmed = raw.trim()
        val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val uri = URI(withScheme)
        require(uri.host?.isNotBlank() == true) { "Remote rule-set URL must include a host" }
        require(uri.scheme.equals("https", ignoreCase = true)) { "Remote rule-set URL must use HTTPS" }
        return buildString {
            append("https://")
            append(uri.host)
            if (uri.port != -1) {
                append(':')
                append(uri.port)
            }
            uri.rawPath?.takeIf { it.isNotBlank() }?.let(::append)
            uri.rawQuery?.let {
                append('?')
                append(it)
            }
            uri.rawFragment?.let {
                append('#')
                append(it)
            }
        }
    }

    private fun requireInlineRuleSet(raw: String) {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Inline rule-set content is required" }
        val normalized = if (trimmed.startsWith("[")) {
            org.json.JSONArray(trimmed)
        } else {
            val root = org.json.JSONObject(trimmed)
            root.optJSONArray("rules")
                ?: throw IllegalArgumentException("Inline rule-set JSON must be a rules array or an object with a rules field")
        }
        require(normalized.length() > 0) { "Inline rule-set must contain at least one rule" }
    }

    private fun sanitizeRoutingRules(rules: RoutingRules): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(rules.proxyPackages)
        return rules.copy(
            proxyPackages = proxyPackages,
            bypassPackages = emptyList(),
            ruleSets = sanitizeRuleSets(rules.ruleSets),
        )
    }

    private fun filteredRoutingPackages(): List<String> {
        val query = _uiState.value.routingAppSearch.trim()
        return _uiState.value.installedApps
            .asSequence()
            .filter { app ->
                query.isBlank() ||
                    app.label.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
            }
            .map { it.packageName }
            .toList()
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                val storage = ProfileStorage(context)
                val subscriptionRefreshScheduler = SubscriptionRefreshScheduler(context)
                val repository = AppRepository(
                    storage = storage,
                    orchestrator = BenchmarkOrchestrator(context, storage),
                    subscriptionRefreshScheduler = subscriptionRefreshScheduler,
                )
                val vpnManager = VpnManager(context, storage)
                val diagnosticsExporter = DiagnosticsExporter(context, storage)
                val installedAppsCatalog = InstalledAppsCatalog(context)
                return MainViewModel(
                    repository = repository,
                    vpnManager = vpnManager,
                    diagnosticsExporter = diagnosticsExporter,
                    installedAppsCatalog = installedAppsCatalog,
                ) as T
            }
        }
    }
}
