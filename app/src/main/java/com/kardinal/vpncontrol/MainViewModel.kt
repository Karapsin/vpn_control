package com.kardinal.vpncontrol

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.kardinal.vpncontrol.data.AppRepository
import com.kardinal.vpncontrol.data.BenchmarkOrchestrator
import com.kardinal.vpncontrol.data.DiagnosticsExporter
import com.kardinal.vpncontrol.data.InstalledAppsCatalog
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch

enum class AppScreen {
    MAIN,
    ROUTING_RULES,
}

data class MainUiState(
    val currentScreen: AppScreen = AppScreen.MAIN,
    val profileUrl: String = "",
    val profileDraft: String = "",
    val customDns: String = "",
    val customDnsDraft: String = "",
    val useCustomDns: Boolean = false,
    val routingRules: RoutingRules = RoutingRules(),
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
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val lastBenchmarkSummary: String = "",
    val statusMessage: String = "Idle",
    val showProfileDialog: Boolean = false,
    val showDnsDialog: Boolean = false,
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
                customDns = persisted.customDns,
                customDnsDraft = if (_uiState.value.showDnsDialog) _uiState.value.customDnsDraft else persisted.customDns,
                useCustomDns = persisted.useCustomDns,
                routingRules = persisted.routingRules,
                selectedProfileName = persisted.selectedProfileName,
                selectedProfileServer = persisted.selectedProfileServer,
                lastBenchmarkSummary = persisted.lastBenchmarkSummary,
                isVpnRunning = persisted.isVpnRunning,
                statusMessage = persisted.statusMessage,
            )
        }.launchIn(viewModelScope)
    }

    fun toggleProfileDialog() {
        _uiState.value = _uiState.value.copy(
            showProfileDialog = !_uiState.value.showProfileDialog,
            profileDraft = _uiState.value.profileUrl,
        )
    }

    fun toggleDnsDialog() {
        _uiState.value = _uiState.value.copy(
            showDnsDialog = !_uiState.value.showDnsDialog,
            customDnsDraft = _uiState.value.customDns,
        )
    }

    fun openRoutingRules() {
        val rules = _uiState.value.routingRules
        _uiState.value = _uiState.value.copy(
            currentScreen = AppScreen.ROUTING_RULES,
            routingProxyPackagesDraft = rules.proxyPackages.toSet(),
            routingBypassPackagesDraft = rules.bypassPackages.toSet(),
            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
            routingAppSearch = "",
        )
        ensureInstalledAppsLoaded()
    }

    fun closeRoutingRules() {
        _uiState.value = _uiState.value.copy(currentScreen = AppScreen.MAIN)
    }

    fun onProfileDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(profileDraft = value)
    }

    fun onDnsDraftChanged(value: String) {
        _uiState.value = _uiState.value.copy(customDnsDraft = value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        _uiState.value = _uiState.value.copy(useCustomDns = enabled)
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
        viewModelScope.launch {
            repository.updateProfileUrl(value)
            repository.updateStatus("Profile updated")
            _uiState.value = _uiState.value.copy(showProfileDialog = false)
        }
    }

    fun saveDns() {
        val dns = _uiState.value.customDnsDraft.trim()
        val enabled = _uiState.value.useCustomDns && dns.isNotBlank()
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
                _uiState.value = _uiState.value.copy(currentScreen = AppScreen.MAIN)
            }
            setBusy(false)
        }
    }

    fun buildRoutingRulesExport(): RoutingRulesExportDocument {
        return RoutingRulesTransfer.export(editedRoutingRules())
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
            if (_uiState.value.profileUrl.isBlank()) {
                repository.updateStatus("Set a profile URL first")
                return@launch
            }
            setBusy(true)
            repository.updateStatus("Refreshing subscription and selecting best location")
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
            setBusy(false)
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

            if (_uiState.value.profileUrl.isBlank()) {
                repository.updateStatus("Set a profile URL first")
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

    private fun editedRoutingRules(): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(_uiState.value.routingProxyPackagesDraft)
        return RoutingRules(
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
                val repository = AppRepository(
                    storage = storage,
                    orchestrator = BenchmarkOrchestrator(context, storage),
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
