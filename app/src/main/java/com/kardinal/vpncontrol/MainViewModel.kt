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
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SubscriptionRefreshScheduler
import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch

enum class AppScreen {
    MAIN,
    LOCATIONS,
    ROUTING_RULES,
}

data class MainUiState(
    val currentScreen: AppScreen = AppScreen.MAIN,
    val screenHistory: List<AppScreen> = emptyList(),
    val profileUrl: String = "",
    val profileDraft: String = "",
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val profileSourceModeDraft: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshPolicyDraft: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshCustomHours: Int = 3,
    val subscriptionRefreshCustomHoursDraft: String = "3",
    val currentLocations: List<String> = emptyList(),
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
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val selectedProfileRawLink: String = "",
    val selectedProfileJson: String = "",
    val lastBenchmarkSummary: String = "",
    val statusMessage: String = "Idle",
    val showProfileDialog: Boolean = false,
    val showDnsDialog: Boolean = false,
    val showRefreshPolicyDialog: Boolean = false,
    val showLocationDialog: Boolean = false,
    val locationDraft: String = "",
    val editingLocationIndex: Int? = null,
    val hasVpnPermission: Boolean = false,
)

class MainViewModel(
    private val repository: AppRepository,
    private val vpnManager: VpnManager,
    private val diagnosticsExporter: DiagnosticsExporter,
    private val installedAppsCatalog: InstalledAppsCatalog,
) : ViewModel() {
    private val _uiState = MutableStateFlow(MainUiState())
    val uiState: StateFlow<MainUiState> = _uiState.asStateFlow()

    init {
        repository.state.onEach { persisted ->
            _uiState.value = _uiState.value.copy(
                profileUrl = persisted.profileUrl,
                profileDraft = if (_uiState.value.showProfileDialog) _uiState.value.profileDraft else persisted.profileUrl,
                profileSourceMode = persisted.profileSourceMode,
                profileSourceModeDraft = if (_uiState.value.showProfileDialog) {
                    _uiState.value.profileSourceModeDraft
                } else {
                    persisted.profileSourceMode
                },
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
                currentLocations = persisted.currentLocations,
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

    fun toggleProfileDialog() {
        _uiState.value = _uiState.value.copy(
            showProfileDialog = !_uiState.value.showProfileDialog,
            profileDraft = _uiState.value.profileUrl,
            profileSourceModeDraft = _uiState.value.profileSourceMode,
        )
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

    fun closeRoutingRules() {
        navigateBack()
    }

    fun openMainTab() {
        navigateToScreen(AppScreen.MAIN)
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

    fun onProfileSourceModeDraftChanged(value: ProfileSourceMode) {
        _uiState.value = _uiState.value.copy(profileSourceModeDraft = value)
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
        val mode = _uiState.value.profileSourceModeDraft
        viewModelScope.launch {
            repository.updateProfileSource(value, mode)
            repository.updateStatus(
                if (mode == ProfileSourceMode.SUBSCRIPTION) {
                    "Profile source set to subscription"
                } else {
                    "Profile source set to current locations"
                },
            )
            _uiState.value = _uiState.value.copy(showProfileDialog = false)
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
                "Subscription refresh policy set to ${policy.displayValue(resolvedHours).lowercase()}",
            )
            _uiState.value = _uiState.value.copy(showRefreshPolicyDialog = false)
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
            if (editIndex == null) {
                nextLocations.add(normalized)
            } else if (editIndex in nextLocations.indices) {
                nextLocations[editIndex] = normalized
            }
            repository.updateCurrentLocations(nextLocations)
            if (replacedRawLink != null && replacedRawLink == selectedLocationReference()) {
                repository.syncSelectedLocation(
                    rawLink = normalized,
                    detail = "Selected location updated",
                )
            }
            repository.updateStatus(
                if (editIndex == null) {
                    "Location added: ${parsed.getOrThrow().remarks}"
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
            repository.updateCurrentLocations(nextLocations)
            val remarks = runCatching { LocationConfigs.decodeStoredLocation(removed).remarks }.getOrDefault("Location")
            repository.updateStatus(
                if (removed == selectedLocationReference()) {
                    "Selected location removed: $remarks"
                } else {
                    "Location removed: $remarks"
                },
            )
        }
    }

    fun selectLocation(index: Int) {
        val rawLink = _uiState.value.currentLocations.getOrNull(index) ?: return
        viewModelScope.launch {
            setBusy(true)
            val isSelected = rawLink == selectedLocationReference()
            val result = if (isSelected) {
                Result.success(Unit)
            } else {
                repository.syncSelectedLocation(
                    rawLink = rawLink,
                    detail = "Selected location manually",
                )
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
            repository.updateCurrentLocations(parsed.getOrThrow())
            repository.updateStatus("Locations imported")
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

    fun refresh() {
        viewModelScope.launch {
            if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION &&
                _uiState.value.profileUrl.isBlank()
            ) {
                repository.updateStatus("Set a subscription URL first")
                return@launch
            }
            if (_uiState.value.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS &&
                _uiState.value.currentLocations.isEmpty()
            ) {
                repository.updateStatus("Add at least one location first")
                return@launch
            }
            setBusy(true)
            _uiState.value = _uiState.value.copy(isRefreshing = true)
            try {
                repository.updateStatus(
                    if (_uiState.value.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                        "Refreshing subscription and selecting best location"
                    } else {
                        "Selecting best location from current locations"
                    },
                )
                val result = repository.refreshBestProfile()
                val message = result.fold(
                    onSuccess = { selection ->
                        "Selected ${selection.profile.remarks}"
                    },
                    onFailure = { error ->
                        error.message ?: "Refresh failed"
                    },
                )
                repository.updateStatus(message)
            } finally {
                _uiState.value = _uiState.value.copy(isRefreshing = false)
                setBusy(false)
            }
        }
    }

    fun toggleVpn() {
        viewModelScope.launch {
            if (_uiState.value.isVpnRunning) {
                setBusy(true)
                val result = vpnManager.stop()
                repository.updateStatus(
                    result.fold(
                        onSuccess = { "VPN stopped" },
                        onFailure = { it.message ?: "Failed to stop VPN" },
                    ),
                )
                setBusy(false)
                return@launch
            }

            if (!_uiState.value.hasVpnPermission) {
                repository.updateStatus("Grant VPN permission and try again")
                return@launch
            }

            setBusy(true)
            repository.updateStatus("Preparing VPN")

            val selection = repository.ensureSelection()
            if (selection.isFailure) {
                repository.updateStatus(selection.exceptionOrNull()?.message ?: "Could not prepare VPN")
                setBusy(false)
                return@launch
            }

            val startResult = vpnManager.start(selection.getOrThrow())
            repository.updateStatus(
                startResult.fold(
                    onSuccess = { "VPN started" },
                    onFailure = { it.message ?: "Failed to start VPN" },
                ),
            )
            setBusy(false)
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

    private fun selectedLocationReference(): String {
        return _uiState.value.selectedProfileJson.ifBlank {
            _uiState.value.selectedProfileRawLink
                .takeIf { it.isNotBlank() }
                ?.let { raw ->
                    runCatching {
                        LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(raw))
                    }.getOrDefault(raw)
                }
                .orEmpty()
        }
    }

    private fun navigateToScreen(screen: AppScreen) {
        val current = _uiState.value.currentScreen
        if (current == screen) return
        _uiState.value = _uiState.value.copy(
            currentScreen = screen,
            screenHistory = _uiState.value.screenHistory + current,
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
