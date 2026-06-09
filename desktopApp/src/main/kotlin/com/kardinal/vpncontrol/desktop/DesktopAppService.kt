package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.nio.file.Path

class DesktopAppService internal constructor(
    private val desktopStore: DesktopStateStore,
    private val runtimeManager: DesktopProxyRuntimeManager,
    private val validationRuntime: DesktopProxyValidationRuntime,
    private val connectionLifecycle: DesktopConnectionLifecycleService,
    private val subscriptionService: DesktopSubscriptionService,
    private val autostartManager: DesktopAutostartManager,
    private val autoRefreshBestSelectionAction: suspend (DesktopAppService) -> Unit,
    initialWorkspace: DesktopWorkspace,
) {
    private var resumeConnectionOnLaunch = initialWorkspace.resumeConnectionOnLaunch ||
        initialWorkspace.persistedState.isVpnRunning
    private var launchResumeAttempted = false

    var desktopLocations by mutableStateOf(initialWorkspace.locations)
        private set

    var state by mutableStateOf(
        restoreDesktopUiState(initialWorkspace.persistedState, initialWorkspace.locations).copy(
            isVpnRunning = false,
            statusMessage = if (resumeConnectionOnLaunch) {
                ConnectionStatusMessages.previousConnectionRestorePending()
            } else {
                initialWorkspace.persistedState.statusMessage
            },
            startOnBootEnabled = autostartManager.isEnabled(),
        ),
    )
        private set

    private val shutdownHook = DesktopRuntimeShutdownHook(runtimeManager::stopBlocking)
    private val connectionActions = DesktopConnectionActionsService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        connectionLifecycle = connectionLifecycle,
        getResumeConnectionOnLaunch = { resumeConnectionOnLaunch },
        setResumeConnectionOnLaunch = { resumeConnectionOnLaunch = it },
        getLaunchResumeAttempted = { launchResumeAttempted },
        setLaunchResumeAttempted = { launchResumeAttempted = it },
        commitState = { nextLocations, nextState ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val locationService = DesktopLocationService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        currentRuntimeMode = { connectionLifecycle.currentRuntimeMode() },
        stopConnection = { message -> connectionActions.stop(message) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val subscriptionManagementService = DesktopSubscriptionManagementService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        validateSubscriptionSource = DesktopSubscriptionSourceValidation::validate,
        stopConnection = { message -> connectionActions.stop(message) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val routingRulesService = DesktopRoutingRulesService(
        stateProvider = { state },
        commitState = { nextState -> commitState(nextState = nextState) },
        updateState = ::updateState,
    )
    private val diagnosticsService = DesktopDiagnosticsService(
        stateProvider = { state },
        desktopStore = desktopStore,
        runtimeManager = runtimeManager,
        updateState = ::updateState,
    )
    private val settingsService = DesktopSettingsService(
        stateProvider = { state },
        autostartManager = autostartManager,
        stopConnection = { message -> connectionActions.stop(message) },
        commitState = { nextState -> commitState(nextState = nextState) },
        updateState = ::updateState,
    )
    private val locationBenchmarkService = DesktopLocationBenchmarkService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        benchmarkLocation = { profile, dnsSettings, benchmarkUrls, settings ->
            validationRuntime.benchmarkLocation(
                profile = profile,
                dnsSettings = dnsSettings,
                benchmarkUrls = benchmarkUrls,
                settings = settings,
            )
        },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val activeConnectionVerifier = DesktopActiveConnectionVerifier()
    private val subscriptionRefreshService = DesktopSubscriptionRefreshService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        subscriptionService = subscriptionService,
        isRuntimeRunning = { connectionLifecycle.isRuntimeRunning() },
        stopConnection = { message -> connectionActions.stop(message) },
        findBestAfterRefresh = { autoRefreshBestSelectionAction(this) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val findBestService = DesktopFindBestService(
        stateProvider = { state },
        visibleLocationsProvider = { locationService.visibleLocations() },
        locationsProvider = { desktopLocations },
        refreshSubscriptions = { subscriptions, statusPrefix ->
            subscriptionRefreshService.refresh(
                subscriptionsToRefresh = subscriptions,
                statusPrefix = statusPrefix,
            )
        },
        startConnection = { location, summary, activeVerificationPort ->
            connectionActions.start(
                location = location,
                benchmarkSummary = summary,
                activeVerificationPort = activeVerificationPort,
            )
        },
        stopConnection = { message -> connectionActions.stop(message) },
        currentRuntimePort = { connectionLifecycle.currentRuntimePort() },
        activeVerificationPortAllocator = activeConnectionVerifier::allocateListenPort,
        verifyActiveConnection = { candidate, appMode, proxyPort, benchmarkUrls, settings ->
            activeConnectionVerifier.verify(
                candidate = candidate,
                appMode = appMode,
                proxyPort = proxyPort,
                url = benchmarkUrls.secondary,
                settings = settings,
            )
        },
        commitState = { nextLocations, nextState ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
        evaluateProfiles = { profiles, dnsSettings, benchmarkUrls, settings, onProgress ->
            validationRuntime.evaluateProfiles(
                profiles = profiles,
                dnsSettings = dnsSettings,
                benchmarkUrls = benchmarkUrls,
                settings = settings,
                onProgress = onProgress,
            )
        },
    )
    private val runtimeStatusService = DesktopRuntimeStatusService(
        stateProvider = { state },
        currentMode = runtimeManager::currentMode,
        currentPort = runtimeManager::currentPort,
        lastPreflightReport = runtimeManager::lastPreflightReport,
        desktopVpnCapabilityStatus = runtimeManager::desktopVpnCapabilityStatus,
        currentLogFile = runtimeManager::currentLogFile,
        defaultLogFile = runtimeManager::defaultLogFile,
    )

    internal fun installShutdownHook(): DesktopAppService {
        runCatching { shutdownHook.install() }
        return this
    }

    internal fun forceRunningStateForTesting(forceRunningState: Boolean) {
        resumeConnectionOnLaunch = forceRunningState
        commitState(
            nextState = state.copy(
                isVpnRunning = forceRunningState,
                hasVpnPermission = true,
            ),
        )
    }

    fun shouldResumeConnectionOnLaunch(): Boolean = connectionActions.shouldResumeConnectionOnLaunch()

    suspend fun resumePreviousConnectionIfNeeded() {
        connectionActions.resumePreviousConnectionIfNeeded()
    }

    suspend fun shutdownForExit() {
        connectionActions.shutdownForExit()
    }

    fun openScreen(screen: AppScreen) {
        updateState { it.copy(currentScreen = screen) }
    }

    fun sourceLabelFor(url: String): String {
        return subscriptionManagementService.sourceLabelFor(url)
    }

    fun runtimeStatusDetails(): List<String> {
        return runtimeStatusService.details()
    }

    fun visibleDesktopLocations(): List<DesktopLocationRecord> {
        return locationService.visibleLocations()
    }

    fun selectedDesktopLocation(): DesktopLocationRecord? {
        return locationService.selectedLocation()
    }

    fun activateSelection(targetId: String) {
        subscriptionManagementService.activateSelection(targetId)
    }

    fun setSourceMode(mode: ProfileSourceMode) {
        subscriptionManagementService.setSourceMode(mode)
    }

    fun toggleAddSubscriptionEditor() {
        subscriptionManagementService.toggleAddSubscriptionEditor()
    }

    fun setProfileDraft(value: String) {
        subscriptionManagementService.setProfileDraft(value)
    }

    fun setProfileTitleDraft(value: String) {
        subscriptionManagementService.setProfileTitleDraft(value)
    }

    fun clearProfileDraft() {
        subscriptionManagementService.clearProfileDraft()
    }

    fun showSubscriptionRenameDialog(subscriptionId: String) {
        subscriptionManagementService.showSubscriptionRenameDialog(subscriptionId)
    }

    fun closeSubscriptionRenameDialog() {
        subscriptionManagementService.closeSubscriptionRenameDialog()
    }

    fun setSubscriptionRenameDraft(value: String) {
        subscriptionManagementService.setSubscriptionRenameDraft(value)
    }

    fun setSubscriptionRenameUrlDraft(value: String) {
        subscriptionManagementService.setSubscriptionRenameUrlDraft(value)
    }

    fun saveSubscriptionRename() {
        subscriptionManagementService.saveSubscriptionRename()
    }

    fun saveSubscriptionDraft() {
        subscriptionManagementService.saveSubscriptionDraft()
    }

    suspend fun deleteSubscription(subscriptionId: String) {
        subscriptionManagementService.deleteSubscription(subscriptionId)
    }

    fun setSubscriptionRefreshPolicyDraft(policy: SubscriptionRefreshPolicy) {
        updateState { it.copy(subscriptionRefreshPolicyDraft = policy) }
    }

    fun setFindBestAfterSubscriptionRefreshDraft(enabled: Boolean) {
        updateState { it.copy(findBestAfterSubscriptionRefreshDraft = enabled) }
    }

    fun setSubscriptionRefreshCustomHoursDraft(value: String) {
        updateState {
            it.copy(subscriptionRefreshCustomHoursDraft = MainCommandLogic.sanitizeDecimalInput(value).take(6))
        }
    }

    fun toggleDnsDialog() {
        settingsService.toggleDnsDialog()
    }

    fun setUseCustomDnsDraft(enabled: Boolean) {
        settingsService.setUseCustomDnsDraft(enabled)
    }

    fun setCustomDnsDraft(value: String) {
        settingsService.setCustomDnsDraft(value)
    }

    fun saveDns() {
        settingsService.saveDns()
    }

    fun setStartOnBootEnabled(enabled: Boolean) {
        settingsService.setStartOnBootEnabled(enabled)
    }

    fun toggleAppModeDialog() {
        settingsService.toggleAppModeDialog()
    }

    fun toggleRefreshPolicyDialog() {
        settingsService.toggleRefreshPolicyDialog()
    }

    fun toggleValidationSettingsDialog() {
        settingsService.toggleValidationSettingsDialog()
    }

    fun toggleLanguageDialog() {
        settingsService.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        settingsService.setAppLanguage(language)
    }

    fun setSubscriptionHwid(value: String) {
        settingsService.setSubscriptionHwid(value)
    }

    fun setValidationPrimaryUrlDraft(value: String) {
        settingsService.setValidationPrimaryUrlDraft(value)
    }

    fun setValidationSecondaryUrlDraft(value: String) {
        settingsService.setValidationSecondaryUrlDraft(value)
    }

    fun setValidationBatchSizeDraft(value: String) {
        settingsService.setValidationBatchSizeDraft(value)
    }

    fun setValidationSubscriptionRefreshConcurrencyDraft(value: String) {
        settingsService.setValidationSubscriptionRefreshConcurrencyDraft(value)
    }

    fun setValidationRetryCountDraft(value: String) {
        settingsService.setValidationRetryCountDraft(value)
    }

    fun saveValidationSettings() {
        settingsService.saveValidationSettings()
    }

    fun saveSubscriptionRefreshPolicy() {
        settingsService.saveSubscriptionRefreshPolicy()
    }

    suspend fun setAppMode(mode: AppMode) {
        settingsService.setAppMode(mode)
    }

    suspend fun toggleAppMode() {
        settingsService.toggleAppMode()
    }

    suspend fun toggleSelectedLocationProxy() {
        connectionActions.toggleSelectedLocationProxy()
    }

    suspend fun refreshAllSubscriptions() {
        subscriptionRefreshService.refreshAll()
    }

    suspend fun refreshActiveSubscriptions() {
        subscriptionRefreshService.refreshActive()
    }

    suspend fun refreshSubscription(subscriptionId: String) {
        subscriptionRefreshService.refreshSubscription(subscriptionId)
    }

    suspend fun runAutoRefreshCycle() {
        subscriptionRefreshService.runAutoRefreshCycle()
    }

    fun addSampleLocation() {
        locationService.addSampleLocation()
    }

    fun editLocation(index: Int) {
        locationService.editLocation(index)
    }

    suspend fun deleteLocation(index: Int) {
        locationService.deleteLocation(index)
    }

    fun applyLocationSelection(index: Int, messagePrefix: String = "Selected") {
        locationService.applySelection(index, messagePrefix)
    }

    fun setRoutingIgnoreRulesDraft(enabled: Boolean) {
        routingRulesService.setIgnoreRulesDraft(enabled)
    }

    fun setRoutingAppSearch(query: String) {
        routingRulesService.setAppSearch(query)
    }

    fun toggleProxyApp(packageName: String) {
        routingRulesService.toggleProxyApp(packageName)
    }

    fun selectAllProxyApps() {
        routingRulesService.selectAllProxyApps()
    }

    fun clearAllProxyApps() {
        routingRulesService.clearAllProxyApps()
    }

    fun setRoutingDirectDomainsDraft(value: String) {
        routingRulesService.setDirectDomainsDraft(value)
    }

    fun addSampleRuleSet() {
        routingRulesService.addSampleRuleSet()
    }

    fun editRuleSet(id: String) {
        routingRulesService.editRuleSet(id)
    }

    fun deleteRuleSet(id: String) {
        routingRulesService.deleteRuleSet(id)
    }

    fun saveRoutingRules() {
        routingRulesService.saveRoutingRules()
    }

    suspend fun stopDesktopProxy(message: String? = null): Result<Unit> {
        return connectionActions.stop(message)
    }

    suspend fun startDesktopProxy(
        location: DesktopLocationRecord,
        benchmarkSummary: String? = null,
    ): Result<Unit> {
        return connectionActions.start(location, benchmarkSummary)
    }

    suspend fun refreshDesktopSubscriptions(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
        stopVpnIfSelectedRemoved: Boolean = true,
    ): Result<Int> {
        return subscriptionRefreshService.refresh(
            subscriptionsToRefresh = subscriptionsToRefresh,
            statusPrefix = statusPrefix,
            stopVpnIfSelectedRemoved = stopVpnIfSelectedRemoved,
        )
    }

    suspend fun importLocationsRaw(raw: String) {
        locationService.importRaw(raw)
    }

    suspend fun importLocationsFromClipboard() {
        locationService.importFromClipboard()
    }

    suspend fun importLocationsFromFile(selection: Result<Path?>) {
        locationService.importFromFile(selection)
    }

    fun exportLocationsToClipboard() {
        locationService.exportToClipboard()
    }

    fun exportLocationsToFile(
        window: ComposeWindow,
        title: String = "Export Locations",
    ) {
        locationService.exportToFile(window, title)
    }

    fun importRoutingRulesRaw(raw: String) {
        routingRulesService.importRaw(raw)
    }

    fun importRoutingRulesFromClipboard() {
        routingRulesService.importFromClipboard()
    }

    fun importRoutingRulesFromFile(
        window: ComposeWindow,
        title: String = "Import Routing Rules",
    ) {
        routingRulesService.importFromFile(window, title)
    }

    fun exportRoutingRulesToClipboard() {
        routingRulesService.exportToClipboard()
    }

    fun exportRoutingRulesToFile(
        window: ComposeWindow,
        title: String = "Export Routing Rules",
    ) {
        routingRulesService.exportToFile(window, title)
    }

    suspend fun exportDiagnostics(selection: Result<Path?>) {
        diagnosticsService.export(selection)
    }

    suspend fun benchmarkLocation(index: Int) {
        locationBenchmarkService.benchmark(index)
    }

    suspend fun findBestLocation(
        refreshSubscriptionsFirst: Boolean = true,
    ) {
        findBestService.findBestLocation(refreshSubscriptionsFirst)
    }

    private fun commitState(
        nextState: MainUiState,
        nextLocations: List<DesktopLocationRecord> = desktopLocations,
    ) {
        val syncedState = syncDesktopUiStateWithLocations(nextState, nextLocations)
        desktopLocations = nextLocations
        state = syncedState
        desktopStore.writeWorkspace(
            DesktopWorkspace(
                persistedState = syncedState.toPersistedState(nextLocations),
                locations = nextLocations,
                resumeConnectionOnLaunch = resumeConnectionOnLaunch,
            ),
        )
    }

    private fun updateState(transform: (MainUiState) -> MainUiState) {
        commitState(transform(state))
    }
}
