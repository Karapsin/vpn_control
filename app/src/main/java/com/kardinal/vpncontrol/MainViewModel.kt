package com.kardinal.vpncontrol

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.kardinal.vpncontrol.data.AppRepository
import com.kardinal.vpncontrol.data.BenchmarkOrchestrator
import com.kardinal.vpncontrol.data.DiagnosticsExporter
import com.kardinal.vpncontrol.data.InstalledAppsCatalog
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SubscriptionRefreshScheduler
import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
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
}

data class MainUiState(
    val currentScreen: AppScreen = AppScreen.MAIN,
    val screenHistory: List<AppScreen> = emptyList(),
    val profileUrl: String = "",
    val profileHistory: List<String> = emptyList(),
    val profileHistoryNames: Map<String, String> = emptyMap(),
    val profileDraft: String = "",
    val showAddSubscriptionEditor: Boolean = false,
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshPolicyDraft: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshCustomHours: Int = 3,
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
    val showDnsDialog: Boolean = false,
    val showRefreshPolicyDialog: Boolean = false,
    val showValidationSettingsDialog: Boolean = false,
    val showProfileHistoryRenameDialog: Boolean = false,
    val profileHistoryRenameSource: String = "",
    val profileHistoryRenameDraft: String = "",
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
                profileHistory = persisted.profileHistory,
                profileHistoryNames = persisted.profileHistoryNames,
                profileDraft = if (_uiState.value.currentScreen == AppScreen.PROFILE) {
                    _uiState.value.profileDraft
                } else {
                    persisted.profileUrl
                },
                profileSourceMode = persisted.profileSourceMode,
                subscriptionRefreshPolicy = persisted.subscriptionRefreshPolicy,
                subscriptionRefreshPolicyDraft = if (_uiState.value.showRefreshPolicyDialog) {
                    _uiState.value.subscriptionRefreshPolicyDraft
                } else {
                    persisted.subscriptionRefreshPolicy
                },
                subscriptionRefreshCustomHours = persisted.subscriptionRefreshCustomHours,
                subscriptionRefreshCustomHoursDraft = if (_uiState.value.showRefreshPolicyDialog) {
                    _uiState.value.subscriptionRefreshCustomHoursDraft
                } else {
                    persisted.subscriptionRefreshCustomHours.toString()
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
                selectedProfileName = persisted.selectedProfileName,
                selectedProfileServer = persisted.selectedProfileServer,
                selectedProfileRawLink = persisted.selectedProfileRawLink,
                selectedProfileJson = persisted.selectedProfileJson,
                selectedProfileSourceUrl = persisted.selectedProfileSourceUrl,
                lastBenchmarkSummary = persisted.lastBenchmarkSummary,
                isVpnRunning = persisted.isVpnRunning,
                statusMessage = persisted.statusMessage,
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

    fun toggleRefreshPolicyDialog() {
        _uiState.value = _uiState.value.copy(
            showRefreshPolicyDialog = !_uiState.value.showRefreshPolicyDialog,
            subscriptionRefreshPolicyDraft = _uiState.value.subscriptionRefreshPolicy,
            subscriptionRefreshCustomHoursDraft = _uiState.value.subscriptionRefreshCustomHours.toString(),
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
            routingBypassPackagesDraft = rules.bypassPackages.toSet(),
            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
            routingAppSearch = "",
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

    fun onDnsDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(customDnsDraft = value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(useCustomDnsDraft = enabled)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        _uiState.value = _uiState.value.copy(subscriptionRefreshPolicyDraft = policy)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(
            subscriptionRefreshCustomHoursDraft = value.filter { it.isDigit() }.take(3),
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

    fun showAddLocationDialog() {
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

    fun onLocationDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(locationDraft = value)
    }

    fun toggleProxyRoutingApp(packageName: String) {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        val nextDirect = _uiState.value.routingBypassPackagesDraft.toMutableSet()
        if (!nextProxy.add(packageName)) {
            nextProxy.remove(packageName)
        } else {
            nextDirect.remove(packageName)
        }
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = nextDirect,
        )
    }

    fun toggleDirectRoutingApp(packageName: String) {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        val nextDirect = _uiState.value.routingBypassPackagesDraft.toMutableSet()
        if (!nextDirect.add(packageName)) {
            nextDirect.remove(packageName)
        } else {
            nextProxy.remove(packageName)
        }
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = nextDirect,
        )
    }

    fun selectAllVisibleProxyApps() {
        val visiblePackages = filteredRoutingPackages()
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.addAll(visiblePackages)
        val nextDirect = _uiState.value.routingBypassPackagesDraft.toMutableSet()
        nextDirect.removeAll(visiblePackages.toSet())
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = nextDirect,
        )
    }

    fun clearAllVisibleProxyApps() {
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(filteredRoutingPackages().toSet())
        _uiState.value = _uiState.value.copy(routingProxyPackagesDraft = nextProxy)
    }

    fun selectAllVisibleDirectApps() {
        val visiblePackages = filteredRoutingPackages()
        val nextDirect = _uiState.value.routingBypassPackagesDraft.toMutableSet()
        nextDirect.addAll(visiblePackages)
        val nextProxy = _uiState.value.routingProxyPackagesDraft.toMutableSet()
        nextProxy.removeAll(visiblePackages.toSet())
        _uiState.value = _uiState.value.copy(
            routingProxyPackagesDraft = nextProxy,
            routingBypassPackagesDraft = nextDirect,
        )
    }

    fun clearAllVisibleDirectApps() {
        val nextDirect = _uiState.value.routingBypassPackagesDraft.toMutableSet()
        nextDirect.removeAll(filteredRoutingPackages().toSet())
        _uiState.value = _uiState.value.copy(routingBypassPackagesDraft = nextDirect)
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
        viewModelScope.launch {
            saveProfileSource("", ProfileSourceMode.SUBSCRIPTION)
        }
    }

    fun useProfileHistoryEntry(source: String) {
        val normalized = source.trim()
        _uiState.value = _uiState.value.copy(
            profileDraft = normalized,
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            showAddSubscriptionEditor = false,
        )
        viewModelScope.launch {
            saveProfileSource(normalized, ProfileSourceMode.SUBSCRIPTION)
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
        val customHours = _uiState.value.subscriptionRefreshCustomHoursDraft.toIntOrNull()
            ?.coerceAtLeast(1)
        viewModelScope.launch {
            if (policy == SubscriptionRefreshPolicy.CUSTOM && customHours == null) {
                repository.updateStatus("Enter a custom refresh interval in hours")
                return@launch
            }
            val resolvedHours = when (policy) {
                SubscriptionRefreshPolicy.OFF -> _uiState.value.subscriptionRefreshCustomHours.coerceAtLeast(1)
                SubscriptionRefreshPolicy.EVERY_HOUR -> 1
                SubscriptionRefreshPolicy.CUSTOM -> customHours ?: _uiState.value.subscriptionRefreshCustomHours.coerceAtLeast(1)
            }
            repository.updateSubscriptionRefreshPolicy(policy, resolvedHours)
            repository.updateStatus(
                "Subscription auto-refresh set to ${policy.displayValue(resolvedHours).lowercase()}",
            )
            _uiState.value = _uiState.value.copy(showRefreshPolicyDialog = false)
        }
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
        val nextLocations = _uiState.value.currentLocations.toMutableList()
        val removed = nextLocations.getOrNull(index) ?: return
        nextLocations.removeAt(index)
        viewModelScope.launch {
            val previousState = repository.snapshot()
            val update = repository.updateCurrentLocations(nextLocations)
            val remarks = runCatching { LocationConfigs.decodeStoredLocation(removed).remarks }.getOrDefault("Location")
            val removedSelected = update.selectedMissing &&
                _uiState.value.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS
            if (removedSelected && _uiState.value.isVpnRunning) {
                val stopResult = vpnManager.stop()
                repository.updateStatus(
                    stopResult.fold(
                        onSuccess = { "Selected location removed. VPN stopped: $remarks" },
                        onFailure = {
                            repository.restoreSnapshot(previousState)
                            it.message ?: "Location removal rolled back because the VPN could not be stopped"
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
        launchTrackedBusyOperation {
            setBusy(true)
            _uiState.value = _uiState.value.copy(isRefreshing = true)
            try {
                val remarks = runCatching { LocationConfigs.decodeStoredLocation(rawLink).remarks }
                    .getOrDefault("Location")
                repository.updateStatus("Checking $remarks...")
                val result = repository.benchmarkLocation(rawLink)
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
                            "Routing rules saved. Restart VPN to apply"
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
                        onSuccess = { "Locations imported. Selected location is no longer available, VPN stopped" },
                        onFailure = {
                            repository.restoreSnapshot(previousState)
                            it.message ?: "Locations import rolled back because the VPN could not be stopped"
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
                            routingBypassPackagesDraft = rules.bypassPackages.toSet(),
                            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
                            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
                        )
                        if (_uiState.value.isVpnRunning) {
                            "Routing rules imported. Restart VPN to apply"
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
                _uiState.value.profileUrl.isBlank()
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
                            statusMessage = "Starting VPN with the best location...",
                        )
                        if (applyResult.isSuccess) {
                            "Best location selected and VPN started: ${selection.profile.remarks}"
                        } else if (applyResult.requiresLiveRollback) {
                            rollbackSelectionChange(
                                previousState = previousState,
                                baseMessage = selectionCommitFailureMessage(
                                    result = applyResult,
                                    applyFailureFallback = "Failed to start VPN with the best location",
                                    persistFailureWithoutApplyFallback = "Failed to save the best location",
                                    persistFailureAfterApplyFallback = "Best location VPN started, but failed to save it",
                                ),
                            )
                        } else {
                            if (applyResult.shouldRestoreSnapshot) {
                                repository.restoreSnapshot(previousState)
                            }
                            selectionCommitFailureMessage(
                                result = applyResult,
                                applyFailureFallback = "Failed to start VPN with the best location",
                                persistFailureWithoutApplyFallback = "Failed to save the best location",
                                persistFailureAfterApplyFallback = "Best location VPN started, but failed to save it",
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
                                onFailure = { "Location search cancelled. ${it.message ?: "Failed to stop VPN."}" },
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
                            onSuccess = { "VPN stopped" },
                            onFailure = { it.message ?: "Failed to stop VPN" },
                        ),
                    )
                } catch (_: CancellationException) {
                    withContext(NonCancellable) {
                        repository.updateStatus("VPN stop cancelled")
                    }
                } finally {
                    setBusy(false)
                }
                return@launchTrackedBusyOperation
            }

            if (!_uiState.value.hasVpnPermission) {
                repository.updateStatus("Grant VPN permission and try again")
                return@launchTrackedBusyOperation
            }

            setBusy(true)
            val previousState = repository.snapshot()
            var startAttempted = false
            try {
                repository.updateStatus("Preparing VPN")

                val selection = repository.ensureSelection()
                if (selection.isFailure) {
                    repository.updateStatus(selection.exceptionOrNull()?.message ?: "Could not prepare VPN")
                    return@launchTrackedBusyOperation
                }

                startAttempted = true
                val applyResult = startAndPersistSelection(
                    selection = selection.getOrThrow(),
                    statusMessage = "Starting VPN...",
                )
                val message = if (applyResult.isSuccess) {
                    "VPN started"
                } else {
                    selectionCommitFailureMessage(
                        result = applyResult,
                        applyFailureFallback = "Failed to start VPN",
                        persistFailureWithoutApplyFallback = "Failed to save the selected location",
                        persistFailureAfterApplyFallback = "VPN started, but failed to save the selected location",
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
                                    "VPN start cancelled"
                                },
                                onFailure = { "VPN start cancelled. ${it.message ?: "Failed to stop VPN."}" },
                            ),
                        )
                    } else {
                        repository.updateStatus("VPN start cancelled")
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
            if (mode == ProfileSourceMode.SUBSCRIPTION && value.isBlank()) {
                "Remote source cleared"
            } else if (mode == ProfileSourceMode.SUBSCRIPTION) {
                "Remote source saved"
            } else {
                "Profile source set to saved locations"
            },
        )
        return Result.success(Unit)
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
                    "$baseMessage Previous VPN location restored."
                },
                onFailure = { restartError ->
                    val stopResult = vpnManager.stop()
                    stopResult.fold(
                        onSuccess = {
                            repository.restoreSnapshot(previousState)
                            "$baseMessage ${restartError.message ?: "Failed to restore the previous VPN location."} " +
                                "VPN stopped to keep state consistent."
                        },
                        onFailure = { stopError ->
                            "$baseMessage ${restartError.message ?: "Failed to restore the previous VPN location."} " +
                                "${stopError.message ?: "Failed to stop the current VPN session."}"
                        },
                    )
                },
            )
        }

        val stopResult = vpnManager.stop()
        return stopResult.fold(
            onSuccess = {
                repository.restoreSnapshot(previousState)
                "$baseMessage VPN stopped to keep state consistent."
            },
            onFailure = { error ->
                "$baseMessage ${error.message ?: "Failed to restore the previous VPN session."}"
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
                "$baseMessage VPN was stopped to keep state consistent."
            },
            onFailure = { stopError ->
                "$baseMessage ${stopError.message ?: "VPN is still running and may not match the saved selection."}"
            },
        )
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
            bypassPackages = RoutingRules.normalizePackageNames(_uiState.value.routingBypassPackagesDraft)
                .filterNot { it in proxyPackages.toSet() },
            nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(_uiState.value.routingNationalDomainsDraft),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(_uiState.value.routingDirectDomainsDraft),
        )
    }

    private fun sanitizeRoutingRules(rules: RoutingRules): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(rules.proxyPackages)
        return rules.copy(
            proxyPackages = proxyPackages,
            bypassPackages = RoutingRules.normalizePackageNames(rules.bypassPackages)
                .filterNot { it in proxyPackages.toSet() },
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
