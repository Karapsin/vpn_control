package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.AutoRefreshLogic
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateProjector
import com.kardinal.vpncontrol.MainUiStateTransitions
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.UnsupportedRemoteSourceResolution
import com.kardinal.vpncontrol.data.parseDirectRemoteSource
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

class DesktopAppService private constructor(
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
                "Previous VPN session will be restored"
            } else {
                initialWorkspace.persistedState.statusMessage
            },
            startOnBootEnabled = autostartManager.isEnabled(),
        ),
    )
        private set

    private val shutdownHookInstalled = AtomicBoolean(false)
    private val shutdownHook = Thread(
        {
            runtimeManager.stopBlocking()
        },
        "vpn-control-runtime-shutdown",
    )
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
        validateSubscriptionSource = ::validateDesktopSubscriptionSource,
        stopConnection = { message -> connectionActions.stop(message) },
        activeConnectionName = ::activeConnectionName,
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
    private val findBestService = DesktopFindBestService(
        stateProvider = { state },
        visibleLocationsProvider = { locationService.visibleLocations() },
        locationsProvider = { desktopLocations },
        refreshSubscriptions = { subscriptions, statusPrefix ->
            refreshDesktopSubscriptions(
                subscriptionsToRefresh = subscriptions,
                statusPrefix = statusPrefix,
            )
        },
        startConnection = connectionActions::start,
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

    companion object {
        fun default(): DesktopAppService {
            val store = DesktopStateStore.default()
            val validationDirectory = store.validationDirectory()
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = store.runtimeDirectory(),
                directProbeRouting = DesktopDirectProbeRouting.forValidationDirectory(validationDirectory),
            )
            return DesktopAppService(
                desktopStore = store,
                runtimeManager = runtimeManager,
                validationRuntime = DesktopProxyValidationRuntime(baseDir = validationDirectory),
                connectionLifecycle = DesktopConnectionLifecycleService(runtimeManager),
                subscriptionService = DesktopSubscriptionService(DesktopSubscriptionDownloadClient()),
                autostartManager = DesktopAutostartManager.default(),
                autoRefreshBestSelectionAction = { service ->
                    service.findBestLocation(refreshSubscriptionsFirst = false)
                },
                initialWorkspace = store.loadWorkspace(defaultDesktopWorkspace()),
            ).installShutdownHook()
        }

        internal fun createForTesting(
            store: DesktopStateStore,
            initialWorkspace: DesktopWorkspace = store.loadWorkspace(defaultDesktopWorkspace()),
            runtimeManager: DesktopProxyRuntimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = store.runtimeDirectory(),
                directProbeRouting = DesktopDirectProbeRouting.forValidationDirectory(store.validationDirectory()),
            ),
            validationRuntime: DesktopProxyValidationRuntime = DesktopProxyValidationRuntime(
                baseDir = store.validationDirectory(),
            ),
            subscriptionContentFetcher: SubscriptionContentFetcher = DesktopSubscriptionDownloadClient(),
            autostartManager: DesktopAutostartManager = DesktopAutostartManager.default(),
            autoRefreshBestSelectionAction: suspend (DesktopAppService) -> Unit = { service ->
                service.findBestLocation(refreshSubscriptionsFirst = false)
            },
            forceRunningState: Boolean? = null,
        ): DesktopAppService {
            val service = DesktopAppService(
                desktopStore = store,
                runtimeManager = runtimeManager,
                validationRuntime = validationRuntime,
                connectionLifecycle = DesktopConnectionLifecycleService(runtimeManager),
                subscriptionService = DesktopSubscriptionService(subscriptionContentFetcher),
                autostartManager = autostartManager,
                autoRefreshBestSelectionAction = autoRefreshBestSelectionAction,
                initialWorkspace = initialWorkspace,
            )
            if (forceRunningState != null) {
                service.resumeConnectionOnLaunch = forceRunningState
                service.commitState(
                    nextState = service.state.copy(
                        isVpnRunning = forceRunningState,
                        hasVpnPermission = true,
                    ),
                )
            }
            return service
        }
    }

    private fun installShutdownHook(): DesktopAppService {
        if (shutdownHookInstalled.compareAndSet(false, true)) {
            runCatching { Runtime.getRuntime().addShutdownHook(shutdownHook) }
        }
        return this
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
        val details = mutableListOf<String>()
        val runtimeMode = runtimeManager.currentMode() ?: state.appMode
        details += StatusMessages.runtimeMode(runtimeMode.name)
        runtimeManager.currentPort()?.let { details += StatusMessages.localProxy("127.0.0.1:$it") }
        if (state.appMode == AppMode.VPN) {
            val preflight = runtimeManager.lastPreflightReport()
            if (preflight != null) {
                details += preflight.summary()
                preflight.checks
                    .filter { it.status == DesktopPreflightStatus.FAIL }
                    .take(2)
                    .forEach { details += it.line() }
            } else {
                details += runtimeManager.desktopVpnCapabilityStatus()
            }
        }
        val logPath = runtimeManager.currentLogFile() ?: runtimeManager.defaultLogFile()
        details += StatusMessages.runtimeLog(logPath.toString())
        return details
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
        if (state.isVpnRunning) {
            stopDesktopProxy()
        } else {
            val location = selectedDesktopLocation()
            if (location == null) {
                updateState { it.withStatus("Select a location first") }
            } else {
                startDesktopProxy(location)
            }
        }
    }

    suspend fun refreshAllSubscriptions() {
        refreshDesktopSubscriptions(
            subscriptionsToRefresh = state.subscriptions.filter { it.url.isNotBlank() },
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(
                state.subscriptions.count { it.url.isNotBlank() },
            ),
        )
    }

    suspend fun refreshActiveSubscriptions() {
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(state)
        if (refreshTargets.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return
        }
        refreshDesktopSubscriptions(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
        )
    }

    suspend fun runAutoRefreshCycle() {
        val plan = AutoRefreshLogic.plan(
            state = state,
            isRuntimeRunning = connectionLifecycle.isRuntimeRunning(),
        ) ?: return
        val refreshResult = refreshDesktopSubscriptions(
            subscriptionsToRefresh = plan.subscriptionsToRefresh,
            statusPrefix = plan.statusPrefix,
            stopVpnIfSelectedRemoved = plan.stopVpnIfSelectedRemoved,
        )
        if (refreshResult.isFailure) return
        if (plan.shouldFindBestAfterRefresh) {
            autoRefreshBestSelectionAction(this)
        }
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

    fun setRoutingNationalDomainsDraft(value: String) {
        routingRulesService.setNationalDomainsDraft(value)
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
        if (subscriptionsToRefresh.isEmpty()) {
            updateState { it.withStatus(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE) }
            return Result.failure(IllegalStateException("No subscriptions to refresh"))
        }

        updateState { it.copy(isBusy = true, isRefreshing = true).withStatus(statusPrefix) }

        val refreshResult = subscriptionService.refreshSubscriptions(
            state = state,
            locations = desktopLocations,
            subscriptionsToRefresh = subscriptionsToRefresh,
            onProgress = { message ->
                updateState { it.withStatus(message) }
            },
        )
        if (refreshResult.isFailure) {
            updateState { it.copy(isBusy = false, isRefreshing = false) }
            return Result.failure(refreshResult.exceptionOrNull() ?: IllegalStateException("Refresh failed"))
        }
        val refreshed = refreshResult.getOrThrow()

        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            refreshed.locations.none { it.matchesSelectedLocation(state) }
        if (removedSelected && state.isVpnRunning && stopVpnIfSelectedRemoved) {
            val stopResult = stopDesktopProxy("${activeConnectionName()} stopped. Refreshed subscriptions removed the selected location.")
            if (stopResult.isFailure) {
                updateState { it.copy(isBusy = false) }
                return Result.failure(stopResult.exceptionOrNull() ?: IllegalStateException("Failed to stop ${activeConnectionName()}"))
            }
        }

        commitState(
            nextLocations = refreshed.locations,
            nextState = state.clearSelectedLocationIf(removedSelected && stopVpnIfSelectedRemoved)
                .copy(
                    isBusy = false,
                    isRefreshing = false,
                    subscriptionHwid = refreshed.subscriptionHwid,
                    subscriptions = refreshed.subscriptions,
                )
                .withStatus(refreshed.statusMessage),
        )
        return Result.success(refreshed.refreshedCount)
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

    private fun validateDesktopSubscriptionSource(raw: String): Result<Unit> {
        return runCatching {
            when (val parsed = parseDirectRemoteSource(raw)) {
                is DirectRemoteSourceResolution -> Unit
                is UnsupportedRemoteSourceResolution -> error(parsed.errorMessage)
                null -> error("Paste a valid https:// subscription URL")
            }
        }
    }

    private fun activeConnectionName(): String {
        return MainCommandLogic.connectionDisplayName(connectionLifecycle.currentRuntimeMode() ?: state.appMode)
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

private fun defaultDesktopWorkspace(): DesktopWorkspace {
    val appMode = defaultDesktopAppMode()
    val persisted = PersistedState(
        appMode = appMode,
        routingRules = RoutingRules(),
        statusMessage = StatusMessages.connectionReadyOnComputer(appMode),
    )
    return DesktopWorkspace(
        persistedState = persisted,
        locations = emptyList(),
    )
}

private fun restoreDesktopUiState(
    persistedState: PersistedState,
    locations: List<DesktopLocationRecord>,
): MainUiState {
    val base = MainUiStateProjector.mergePersistedState(
        current = MainUiState(
            currentScreen = AppScreen.MAIN,
            installedApps = emptyList(),
            installedAppsLoaded = true,
            hasVpnPermission = true,
        ),
        persisted = persistedState,
    )
    return syncDesktopUiStateWithLocations(
        state = base.copy(
            subscriptionRefreshPolicyDraft = persistedState.subscriptionRefreshPolicy,
            findBestAfterSubscriptionRefreshDraft = persistedState.findBestAfterSubscriptionRefresh,
            subscriptionRefreshCustomHoursDraft = persistedState.subscriptionRefreshCustomHours.toString(),
            installedApps = emptyList(),
            installedAppsLoaded = true,
            installedAppsLoading = false,
            hasVpnPermission = true,
            routingIgnoreRulesDraft = persistedState.routingRules.ignoreRules,
            routingProxyPackagesDraft = persistedState.routingRules.proxyPackages.toSet(),
            routingNationalDomainsDraft = persistedState.routingRules.nationalDomainSuffixes.joinToString("\n"),
            routingDirectDomainsDraft = persistedState.routingRules.directDomainSuffixes.joinToString("\n"),
            routingRuleSetsDraft = emptyList(),
        ),
        locations = locations,
    )
}

internal fun BenchmarkValidationSettings.toDesktopValidationSettings(): DesktopValidationSettings {
    val normalized = normalized()
    val concurrency = minOf(normalized.batchSize.coerceAtLeast(1), 5)
    return DesktopValidationSettings(
        preflightConcurrency = concurrency,
        batchSize = normalized.batchSize,
    )
}

private fun syncDesktopUiStateWithLocations(
    state: MainUiState,
    locations: List<DesktopLocationRecord>,
): MainUiState {
    val syncedSubscriptions = syncSubscriptionsWithLocations(state.subscriptions, locations)
    val savedLocations = locations.filter { it.sourceUrl.isBlank() }
    val effectiveActiveSubscriptionId = when {
        isAllSubscriptionsGroupActive(state.activeSubscriptionId, syncedSubscriptions) -> ALL_SUBSCRIPTIONS_ID
        state.activeSubscriptionId.isBlank() -> syncedSubscriptions.firstOrNull()?.id.orEmpty()
        syncedSubscriptions.none { it.id == state.activeSubscriptionId } -> syncedSubscriptions.firstOrNull()?.id.orEmpty()
        else -> state.activeSubscriptionId
    }
    val visibleCurrentLocations = when (state.profileSourceMode) {
        ProfileSourceMode.SUBSCRIPTION -> when {
            isAllSubscriptionsGroupActive(effectiveActiveSubscriptionId, syncedSubscriptions) ->
                mergedSubscriptionLocations(syncedSubscriptions)
            else ->
                syncedSubscriptions.firstOrNull { it.id == effectiveActiveSubscriptionId }
                    ?.cachedLocations
                    .orEmpty()
        }
        ProfileSourceMode.CURRENT_LOCATIONS -> savedLocations.map(DesktopLocationRecord::rawLink)
    }
    val selectedLocation = locations.firstOrNull { it.matchesSelectedLocation(state) }
    return state.copy(
        subscriptions = syncedSubscriptions,
        activeSubscriptionId = effectiveActiveSubscriptionId,
        profileUrl = when {
            isAllSubscriptionsGroupActive(effectiveActiveSubscriptionId, syncedSubscriptions) -> ""
            else -> syncedSubscriptions.firstOrNull { it.id == effectiveActiveSubscriptionId }?.url.orEmpty()
        },
        profileHistory = syncedSubscriptions.map(SubscriptionSource::url),
        profileHistoryNames = syncedSubscriptions
            .filter { it.customName.isNotBlank() }
            .associate { it.url to it.customName },
        currentLocations = visibleCurrentLocations,
        locationBenchmarkDetails = locations.associate { it.rawLink to it.benchmarkDetail },
        selectedProfileName = selectedLocation?.name ?: state.selectedProfileName.takeIf { it.isNotBlank() }.orEmpty(),
        selectedProfileServer = selectedLocation?.server ?: state.selectedProfileServer.takeIf { it.isNotBlank() }.orEmpty(),
        selectedProfileRawLink = selectedLocation?.rawLink ?: state.selectedProfileRawLink.takeIf { raw ->
            raw.isNotBlank() && locations.any { it.rawLink == raw }
        }.orEmpty(),
        selectedProfileSourceUrl = selectedLocation?.sourceUrl ?: state.selectedProfileSourceUrl.takeIf { url ->
            url.isNotBlank() && locations.any { it.sourceUrl == url }
        }.orEmpty(),
    )
}

private fun syncSubscriptionsWithLocations(
    subscriptions: List<SubscriptionSource>,
    locations: List<DesktopLocationRecord>,
): List<SubscriptionSource> {
    val groupedLocations = locations
        .filter { it.sourceUrl.isNotBlank() }
        .groupBy(DesktopLocationRecord::sourceUrl)
        .mapValues { (_, values) -> values.map(DesktopLocationRecord::rawLink) }
    return subscriptions.map { subscription ->
        subscription.copy(cachedLocations = groupedLocations[subscription.url].orEmpty())
    }
}

private fun MainUiState.toPersistedState(
    locations: List<DesktopLocationRecord>,
): PersistedState {
    val synced = syncDesktopUiStateWithLocations(this, locations)
    val routingRules = RoutingRules(
        ignoreRules = synced.routingIgnoreRulesDraft,
        proxyPackages = RoutingRules.normalizePackageNames(synced.routingProxyPackagesDraft),
        bypassPackages = emptyList(),
        nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(synced.routingNationalDomainsDraft),
        directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(synced.routingDirectDomainsDraft),
        ruleSets = emptyList(),
    )
    return PersistedState(
        appLanguage = synced.appLanguage,
        subscriptionHwid = synced.subscriptionHwid,
        profileUrl = synced.profileUrl,
        activeSubscriptionId = synced.activeSubscriptionId,
        subscriptions = synced.subscriptions,
        profileHistory = synced.profileHistory,
        profileHistoryNames = synced.profileHistoryNames,
        profileSourceMode = synced.profileSourceMode,
        appMode = synced.appMode,
        subscriptionRefreshPolicy = synced.subscriptionRefreshPolicy,
        findBestAfterSubscriptionRefresh = synced.findBestAfterSubscriptionRefresh,
        subscriptionRefreshCustomHours = synced.subscriptionRefreshCustomHours,
        validationSettings = synced.validationSettings,
        savedLocations = locations.filter { it.sourceUrl.isBlank() }.map(DesktopLocationRecord::rawLink),
        currentLocations = synced.currentLocations,
        locationBenchmarkDetails = synced.locationBenchmarkDetails,
        customDns = synced.customDns,
        useCustomDns = synced.useCustomDns,
        routingRules = routingRules,
        selectedProfileName = synced.selectedProfileName,
        selectedProfileServer = synced.selectedProfileServer,
        selectedProfileRawLink = synced.selectedProfileRawLink,
        selectedProfileJson = synced.selectedProfileJson,
        selectedProfileSourceUrl = synced.selectedProfileSourceUrl,
        lastBenchmarkSummary = synced.lastBenchmarkSummary,
        runtimeConfigJson = "",
        statusMessage = synced.statusMessage,
        isVpnRunning = synced.isVpnRunning,
        sessionStatsEnabled = synced.sessionStatsEnabled,
        liveTrafficStatsEnabled = synced.liveTrafficStatsEnabled,
        profileTotalsEnabled = synced.profileTotalsEnabled,
        latencyHistoryEnabled = synced.latencyHistoryEnabled,
        connectionLogEnabled = synced.connectionLogEnabled,
        connectionTestToolsEnabled = synced.connectionTestToolsEnabled,
        sessionStartedAtEpochMillis = synced.sessionStartedAtEpochMillis,
        sessionStoppedAtEpochMillis = synced.sessionStoppedAtEpochMillis,
        sessionStartRxBytes = synced.sessionStartRxBytes,
        sessionStartTxBytes = synced.sessionStartTxBytes,
        successfulStarts = synced.successfulStarts,
        successfulStops = synced.successfulStops,
        profileTrafficTotals = synced.profileTrafficTotals,
        latencyHistory = synced.latencyHistory,
        connectionLog = synced.connectionLog,
    )
}

internal fun String.toCompactBenchmarkLabel(): String {
    val primary = Regex("""primary=([a-z]+)""").find(this)?.groupValues?.getOrNull(1)
    val secondary = Regex("""secondary=([a-z]+)""").find(this)?.groupValues?.getOrNull(1)
    val tcp = Regex("""tcp=([0-9.]+ms|unreachable)""").find(this)?.groupValues?.getOrNull(1)
    return when {
        primary != null && secondary != null && tcp != null ->
            "primary $primary • secondary $secondary • tcp $tcp"
        primary != null && secondary != null ->
            "primary $primary • secondary $secondary"
        contains("tcp=") -> replace(':', ' ').trim()
        else -> this
    }
}

internal fun benchmarkDetailIndicatesSelectable(detail: String, previousIsValid: Boolean): Boolean {
    val primary = Regex("""(?:^|\s)primary[= ]([a-z]+)""").find(detail)?.groupValues?.getOrNull(1)
    if (primary != null) {
        return primary == "ok"
    }

    if (detail.contains("tcp_unreachable")) {
        return false
    }

    val tcp = Regex("""(?:^|\s)tcp[= ]([0-9.]+ms|unreachable)""").find(detail)?.groupValues?.getOrNull(1)
    if (tcp != null) {
        return tcp != "unreachable"
    }

    return previousIsValid
}
