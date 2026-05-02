package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.AutoRefreshLogic
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateProjector
import com.kardinal.vpncontrol.MainUiStateTransitions
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.LocationConfigs
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
import com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.withTimeoutOrNull

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
    private val locationService = DesktopLocationService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        currentRuntimeMode = { connectionLifecycle.currentRuntimeMode() },
        stopConnection = { message -> stopDesktopProxy(message) },
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

    fun shouldResumeConnectionOnLaunch(): Boolean = resumeConnectionOnLaunch

    suspend fun resumePreviousConnectionIfNeeded() {
        if (launchResumeAttempted || !resumeConnectionOnLaunch || state.isVpnRunning || state.isBusy) {
            return
        }
        launchResumeAttempted = true
        val location = selectedDesktopLocation()
        if (location == null) {
            updateState {
                it.copy(isBusy = false, isVpnRunning = false)
                    .withStatus("Previous VPN location is no longer available")
            }
            return
        }
        updateState {
            it.withStatus("Restoring VPN: ${location.name}...")
        }
        startDesktopProxy(
            location = location,
            benchmarkSummary = state.lastBenchmarkSummary,
        )
    }

    suspend fun shutdownForExit() {
        stopRuntimeForAppExit()
    }

    fun openScreen(screen: AppScreen) {
        updateState { it.copy(currentScreen = screen) }
    }

    fun sourceLabelFor(url: String): String {
        return state.subscriptions
            .firstOrNull { it.url == url }
            ?.customName
            ?.takeIf(String::isNotBlank)
            ?: url.takeIf(String::isNotBlank)
                ?.substringAfter("://")
                ?.substringBefore('/')
            ?: "none"
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
        updateState {
            it.withStatus(
                if (targetId == ALL_SUBSCRIPTIONS_ID) {
                    "Activated all subscriptions"
                } else {
                    "Activated ${sourceLabelFor(it.subscriptions.first { subscription -> subscription.id == targetId }.url)}"
                },
            ).copy(
                activeSubscriptionId = targetId,
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                profileUrl = if (targetId == ALL_SUBSCRIPTIONS_ID) {
                    it.profileUrl
                } else {
                    it.subscriptions.first { subscription -> subscription.id == targetId }.url
                },
            )
        }
    }

    fun setSourceMode(mode: ProfileSourceMode) {
        updateState { it.withStatus("Profile source mode: ${mode.name}").copy(profileSourceMode = mode) }
    }

    fun toggleAddSubscriptionEditor() {
        updateState { current ->
            current.copy(
                showAddSubscriptionEditor = !current.showAddSubscriptionEditor,
                profileDraft = if (current.showAddSubscriptionEditor) current.profileDraft else current.profileUrl,
            )
        }
    }

    fun setProfileDraft(value: String) {
        updateState { it.copy(profileDraft = value) }
    }

    fun clearProfileDraft() {
        updateState { it.copy(profileDraft = "") }
    }

    fun showSubscriptionRenameDialog(subscriptionId: String) {
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId } ?: return
        updateState {
            it.copy(
                showProfileHistoryRenameDialog = true,
                profileHistoryRenameSource = target.url,
                profileHistoryRenameDraft = target.customName,
            )
        }
    }

    fun closeSubscriptionRenameDialog() {
        updateState {
            it.copy(
                showProfileHistoryRenameDialog = false,
                profileHistoryRenameSource = "",
                profileHistoryRenameDraft = "",
            )
        }
    }

    fun setSubscriptionRenameDraft(value: String) {
        updateState { it.copy(profileHistoryRenameDraft = value.take(80)) }
    }

    fun saveSubscriptionRename() {
        val source = state.profileHistoryRenameSource.trim()
        if (source.isBlank()) {
            closeSubscriptionRenameDialog()
            return
        }
        val normalizedName = state.profileHistoryRenameDraft.trim()
        val updatedSubscriptions = state.subscriptions.map { subscription ->
            if (subscription.url == source) {
                subscription.copy(customName = normalizedName)
            } else {
                subscription
            }
        }
        commitState(
            nextState = state.copy(
                subscriptions = updatedSubscriptions,
                showProfileHistoryRenameDialog = false,
                profileHistoryRenameSource = "",
                profileHistoryRenameDraft = "",
            ).withStatus(
                if (normalizedName.isBlank()) {
                    "Subscription name reset"
                } else {
                    "Subscription name saved"
                },
            ),
        )
    }

    fun saveSubscriptionDraft() {
        val trimmed = state.profileDraft.trim()
        val validation = MainCommandLogic.validateProfileSourceSave(
            value = trimmed,
            mode = ProfileSourceMode.SUBSCRIPTION,
            validateSubscription = ::validateDesktopSubscriptionSource,
        )
        if (validation.isFailure) {
            updateState {
                it.withStatus(validation.exceptionOrNull()?.message ?: "Invalid subscription URL")
            }
            return
        }

        val existingIndex = state.subscriptions.indexOfFirst { it.url == trimmed }
        val existing = state.subscriptions.getOrNull(existingIndex)
        val target = existing ?: SubscriptionSource(
            id = UUID.randomUUID().toString(),
            url = trimmed,
            customName = state.profileHistoryNames[trimmed].orEmpty(),
        )
        val updatedSubscriptions = buildList {
            add(target)
            state.subscriptions.forEachIndexed { index, subscription ->
                if (index != existingIndex) {
                    add(subscription)
                }
            }
        }
        commitState(
            nextState = state.copy(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                activeSubscriptionId = target.id,
                profileUrl = target.url,
                subscriptions = updatedSubscriptions,
                profileDraft = target.url,
                showAddSubscriptionEditor = false,
            ).withStatus(validation.getOrThrow()),
        )
    }

    suspend fun deleteSubscription(subscriptionId: String) {
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId } ?: return
        val nextSubscriptions = state.subscriptions.filterNot { it.id == subscriptionId }
        val nextLocations = desktopLocations.filterNot { it.sourceUrl == target.url }
        val removedSelected = state.selectedProfileSourceUrl == target.url ||
            (state.selectedProfileRawLink.isNotBlank() && nextLocations.none { it.rawLink == state.selectedProfileRawLink })

        if (removedSelected && state.isVpnRunning) {
            val stopResult = stopDesktopProxy("${activeConnectionName()} stopped. Deleted subscription removed the selected location.")
            if (stopResult.isFailure) {
                return
            }
        }

        val nextActiveId = when {
            nextSubscriptions.isEmpty() -> ""
            isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) &&
                nextSubscriptions.size > 1 -> ALL_SUBSCRIPTIONS_ID
            state.activeSubscriptionId == subscriptionId -> nextSubscriptions.first().id
            else -> state.activeSubscriptionId
        }

        commitState(
            nextLocations = nextLocations,
            nextState = state.clearSelectedLocationIf(removedSelected).copy(
                subscriptions = nextSubscriptions,
                activeSubscriptionId = nextActiveId,
                profileUrl = when {
                    nextActiveId.isBlank() -> ""
                    isAllSubscriptionsGroupActive(nextActiveId, nextSubscriptions) -> ""
                    else -> nextSubscriptions.firstOrNull { it.id == nextActiveId }?.url.orEmpty()
                },
                profileDraft = if (state.profileDraft.trim() == target.url) "" else state.profileDraft,
                showAddSubscriptionEditor = if (state.profileDraft.trim() == target.url) false else state.showAddSubscriptionEditor,
            ).withStatus("Subscription deleted"),
        )
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
        updateState {
            if (it.showDnsDialog) {
                it.copy(showDnsDialog = false)
            } else {
                it.copy(
                    showDnsDialog = true,
                    customDnsDraft = it.customDns,
                    useCustomDnsDraft = it.useCustomDns,
                )
            }
        }
    }

    fun setUseCustomDnsDraft(enabled: Boolean) {
        updateState { it.copy(useCustomDnsDraft = enabled) }
    }

    fun setCustomDnsDraft(value: String) {
        updateState { it.copy(customDnsDraft = value.take(80)) }
    }

    fun saveDns() {
        val plan = MainDraftLogic.resolveDnsSave(state)
        commitState(
            nextState = state.copy(
                customDns = plan.dns,
                customDnsDraft = plan.dns,
                useCustomDns = plan.enabled,
                useCustomDnsDraft = plan.enabled,
                showDnsDialog = false,
            ).withStatus(plan.statusMessage),
        )
    }

    fun setStartOnBootEnabled(enabled: Boolean) {
        val result = autostartManager.setEnabled(enabled)
        val actual = autostartManager.isEnabled()
        val status = if (result.isSuccess) {
            if (actual) {
                "App will start automatically after login"
            } else {
                "App startup on login disabled"
            }
        } else {
            result.exceptionOrNull()?.message ?: "Failed to update startup setting"
        }
        updateState { it.copy(startOnBootEnabled = actual).withStatus(status) }
    }

    fun toggleAppModeDialog() {
        updateState { it.copy(showAppModeDialog = !it.showAppModeDialog) }
    }

    fun toggleRefreshPolicyDialog() {
        updateState(MainUiStateTransitions::toggleRefreshPolicyDialog)
    }

    fun toggleValidationSettingsDialog() {
        updateState(MainUiStateTransitions::toggleValidationSettingsDialog)
    }

    fun toggleLanguageDialog() {
        updateState { it.copy(showLanguageDialog = !it.showLanguageDialog) }
    }

    fun setAppLanguage(language: AppLanguage) {
        updateState {
            it.copy(appLanguage = language, showLanguageDialog = false).withStatus(
                StatusMessages.languageSet(if (language == AppLanguage.SYSTEM) "" else language.nativeName),
            )
        }
    }

    fun setSubscriptionHwid(value: String) {
        val normalized = value.trim()
        val status = if (normalized.isBlank()) {
            "Subscription x-hwid cleared. A new ID will be generated on the next refresh."
        } else {
            "Subscription x-hwid saved. Refresh the subscription to use it."
        }
        updateState { it.copy(subscriptionHwid = normalized).withStatus(status) }
    }

    fun setValidationPrimaryUrlDraft(value: String) {
        updateState { it.copy(validationPrimaryUrlDraft = value) }
    }

    fun setValidationSecondaryUrlDraft(value: String) {
        updateState { it.copy(validationSecondaryUrlDraft = value) }
    }

    fun setValidationBatchSizeDraft(value: String) {
        updateState { it.copy(validationBatchSizeDraft = value.filter(Char::isDigit).take(3)) }
    }

    fun setValidationRetryCountDraft(value: String) {
        updateState { it.copy(validationRetryCountDraft = value.filter(Char::isDigit).take(3)) }
    }

    fun saveValidationSettings() {
        val plan = MainDraftLogic.resolveValidationSettingsSave(state)
        val settings = plan.settings
        commitState(
            nextState = state.copy(
                validationSettings = settings,
                validationPrimaryUrlDraft = settings.primaryUrl,
                validationSecondaryUrlDraft = settings.secondaryUrl,
                validationBatchSizeDraft = settings.batchSize.toString(),
                validationRetryCountDraft = settings.retryCount.toString(),
                showValidationSettingsDialog = false,
            ).withStatus(plan.statusMessage),
        )
    }

    fun saveSubscriptionRefreshPolicy() {
        val resolution = MainCommandLogic.resolveSubscriptionRefreshPolicySave(state)
        if (resolution.isFailure) {
            updateState {
                it.withStatus(
                    resolution.exceptionOrNull()?.message ?: "Failed to save refresh settings",
                )
            }
            return
        }
        val saved = resolution.getOrThrow()
        commitState(
            nextState = state.copy(
                subscriptionRefreshPolicy = saved.policy,
                subscriptionRefreshPolicyDraft = saved.policy,
                findBestAfterSubscriptionRefresh = saved.findBestAfterRefresh,
                findBestAfterSubscriptionRefreshDraft = saved.findBestAfterRefresh,
                subscriptionRefreshCustomHours = saved.resolvedHours,
                subscriptionRefreshCustomHoursDraft = formatSubscriptionRefreshHoursInput(saved.resolvedHours),
                showRefreshPolicyDialog = false,
            ).withStatus(saved.statusMessage),
        )
    }

    suspend fun setAppMode(mode: AppMode) {
        if (state.isVpnRunning && mode != state.appMode) {
            val stopResult = stopDesktopProxy("${MainCommandLogic.connectionDisplayName(state.appMode)} stopped. App mode: ${mode.name}")
            if (stopResult.isFailure) {
                return
            }
        }
        updateState { it.withStatus("App mode: ${mode.name}").copy(appMode = mode, showAppModeDialog = false) }
    }

    suspend fun toggleAppMode() {
        val nextMode = if (state.appMode == AppMode.VPN) {
            AppMode.PROXY_ONLY
        } else {
            AppMode.VPN
        }
        setAppMode(nextMode)
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
        return connectionLifecycle.stopConnection(
            state = state,
            locations = desktopLocations,
            message = message,
            currentState = { state },
            setResumeConnectionOnLaunch = { resumeConnectionOnLaunch = it },
            commitState = { nextLocations, nextState ->
                commitState(nextState = nextState, nextLocations = nextLocations)
            },
            updateState = ::updateState,
        )
    }

    private suspend fun stopRuntimeForAppExit(): Result<Unit> {
        return connectionLifecycle.stopRuntimeForAppExit(
            state = state,
            locations = desktopLocations,
            currentState = { state },
            setResumeConnectionOnLaunch = { resumeConnectionOnLaunch = it },
            commitState = { nextLocations, nextState ->
                commitState(nextState = nextState, nextLocations = nextLocations)
            },
            updateState = ::updateState,
        )
    }

    suspend fun startDesktopProxy(
        location: DesktopLocationRecord,
        benchmarkSummary: String? = null,
    ): Result<Unit> {
        return connectionLifecycle.startConnection(
            state = state,
            locations = desktopLocations,
            location = location,
            benchmarkSummary = benchmarkSummary,
            currentState = { state },
            setResumeConnectionOnLaunch = { resumeConnectionOnLaunch = it },
            commitState = { nextLocations, nextState ->
                commitState(nextState = nextState, nextLocations = nextLocations)
            },
            updateState = ::updateState,
        )
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
        if (selection.isFailure) {
            updateState { it.withStatus(selection.exceptionOrNull()?.message ?: "Failed to open diagnostics destination") }
            return
        }
        val target = selection.getOrNull() ?: run {
            updateState { it.withStatus("Diagnostics export canceled") }
            return
        }
        val report = DesktopDiagnosticsExporter.buildReport(
            state = state,
            runtimeMode = runtimeManager.currentMode(),
            currentPort = runtimeManager.currentPort(),
            runtimeProcessId = runtimeManager.currentProcessId(),
            logFile = runtimeManager.currentLogFile() ?: runtimeManager.defaultLogFile(),
            runtimeConfigJson = desktopStore.readRuntimeConfig() ?: runtimeManager.lastAttemptedConfigJson(),
            preflightReport = runtimeManager.lastPreflightReport(),
            vpnCapabilityStatus = runtimeManager.desktopVpnCapabilityStatus(),
        )
        val result = DesktopTextTransfer.writeTextFile(target, report)
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path ->
                        "Diagnostics exported to $path"
                    },
                    onFailure = { error -> error.message ?: "Failed to export diagnostics" },
                ),
            )
        }
    }

    suspend fun benchmarkLocation(index: Int) {
        val location = desktopLocations.firstOrNull { it.index == index } ?: return
        val profile = runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }
        if (profile.isFailure) {
            updateState { it.withStatus(profile.exceptionOrNull()?.message ?: "Invalid location config") }
            return
        }
        updateState { it.copy(isBusy = true).withStatus("Testing ${location.name}...") }
        val validationSettings = state.validationSettings.normalized()
        val benchmark = validationRuntime.benchmarkLocation(
            profile = profile.getOrThrow(),
            dnsSettings = DesktopDnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            ),
            benchmarkUrls = BenchmarkUrls(
                primary = validationSettings.primaryUrl,
                secondary = validationSettings.secondaryUrl,
            ),
            settings = validationSettings.toDesktopValidationSettings(),
        )
        if (benchmark.isSuccess) {
            val result = benchmark.getOrThrow()
            val updatedLocations = desktopLocations.map { existing ->
                if (existing.index == index) {
                    existing.copy(
                        benchmarkDetail = result.detail.toCompactBenchmarkLabel(),
                        isValid = result.primaryStatus == "ok",
                    )
                } else {
                    existing
                }
            }
            commitState(
                nextLocations = updatedLocations,
                nextState = state.copy(isBusy = false).withStatus(
                    "Benchmarked ${location.name}: ${result.primaryStatus} / ${result.secondaryStatus}",
                ),
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    benchmark.exceptionOrNull()?.message ?: "Failed to benchmark ${location.name}",
                )
            }
        }
    }

    suspend fun findBestLocation(
        refreshSubscriptionsFirst: Boolean = true,
    ) {
        val preconditionError = MainCommandLogic.refreshPreconditionError(state)
        if (preconditionError != null) {
            updateState { it.withStatus(preconditionError) }
            return
        }
        if (refreshSubscriptionsFirst && state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(state)
            val refreshResult = refreshDesktopSubscriptions(
                subscriptionsToRefresh = refreshTargets,
                statusPrefix = SubscriptionRefreshResultLogic.refreshStartMessage(refreshTargets.size),
            )
            if (refreshResult.isFailure) {
                return
            }
        }
        val profiles = visibleDesktopLocations().mapNotNull { location ->
            runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }.getOrNull()
        }
        if (profiles.isEmpty()) {
            updateState { it.withStatus("No locations available for benchmarking") }
            return
        }
        updateState {
            it.copy(isBusy = true, isRefreshing = true).withStatus(
                "${MainCommandLogic.refreshStartMessage(it)} Testing fastest candidates in batches...",
            )
        }
        val validationSettings = state.validationSettings.normalized()
        val desktopValidationSettings = validationSettings.toDesktopValidationSettings()
        val evaluation = withTimeoutOrNull(desktopValidationSettings.searchTimeoutMillis) {
            validationRuntime.evaluateProfiles(
                profiles = profiles,
                dnsSettings = DesktopDnsSettings(
                    enabled = state.useCustomDns,
                    value = state.customDns,
                ),
                benchmarkUrls = BenchmarkUrls(
                    primary = validationSettings.primaryUrl,
                    secondary = validationSettings.secondaryUrl,
                ),
                settings = desktopValidationSettings,
                onProgress = { progress ->
                    updateState {
                        it.copy(isBusy = true, isRefreshing = true).withStatus(progress)
                    }
                },
            )
        } ?: run {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    "Best location search timed out; keeping the current connection",
                )
            }
            return
        }
        val winning = evaluation.winner ?: evaluation.fallback
        val winningRawKey = winning?.let { LocationConfigs.encodeStoredLocation(it.profile) }
        updateLocationBenchmarks(
            detailsByRawKey = evaluation.locationBenchmarkDetails,
            winningRawKey = winningRawKey,
        )
        if (winning == null) {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus(
                    evaluation.failureMessage ?: "No suitable location found",
                )
            }
            return
        }
        val winnerLocation = desktopLocations.firstOrNull { it.normalizedStorageKey() == winningRawKey }
        if (winnerLocation == null) {
            updateState {
                it.copy(isBusy = false, isRefreshing = false).withStatus("Best location could not be mapped to the desktop list")
            }
            return
        }
        startDesktopProxy(
            location = winnerLocation,
            benchmarkSummary = "Best: ${winning.profile.remarks} • ${winning.detail.toCompactBenchmarkLabel()}",
        )
        updateState { it.copy(isRefreshing = false) }
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

    private fun updateLocationBenchmarks(
        detailsByRawKey: Map<String, String>,
        winningRawKey: String? = null,
    ) {
        if (detailsByRawKey.isEmpty()) return
        val updatedLocations = desktopLocations.map { location ->
            val normalized = location.normalizedStorageKey()
            val detail = detailsByRawKey[normalized] ?: return@map location
            location.copy(
                benchmarkDetail = detail.toCompactBenchmarkLabel(),
                isValid = benchmarkDetailIndicatesSelectable(detail, location.isValid),
                isSelected = if (winningRawKey != null) {
                    normalized == winningRawKey
                } else {
                    location.isSelected
                },
            )
        }
        commitState(nextLocations = updatedLocations, nextState = state)
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

private fun BenchmarkValidationSettings.toDesktopValidationSettings(): DesktopValidationSettings {
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

private fun DesktopLocationRecord.toCompactBenchmarkMillis(): Double? {
    val match = Regex("""(\d+(?:\.\d+)?)\s*ms""").find(benchmarkDetail)
    return match?.groupValues?.getOrNull(1)?.toDoubleOrNull()
}

private fun String.toCompactBenchmarkLabel(): String {
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
