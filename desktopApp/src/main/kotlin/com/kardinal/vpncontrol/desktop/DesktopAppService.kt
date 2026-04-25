package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.LocationMutationLogic
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateProjector
import com.kardinal.vpncontrol.MainUiStateTransitions
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.ResolvedRemoteSource
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SelectionWorkflowService
import com.kardinal.vpncontrol.data.UnsupportedRemoteSourceResolution
import com.kardinal.vpncontrol.data.displayRemoteSourceHost
import com.kardinal.vpncontrol.data.parseDirectRemoteSource
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.VlessProfile
import com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.util.UUID
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean

class DesktopAppService private constructor(
    private val desktopStore: DesktopStateStore,
    private val runtimeManager: DesktopProxyRuntimeManager,
    private val validationRuntime: DesktopProxyValidationRuntime,
    private val subscriptionContentFetcher: SubscriptionContentFetcher,
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

    companion object {
        fun default(): DesktopAppService {
            val store = DesktopStateStore.default()
            return DesktopAppService(
                desktopStore = store,
                runtimeManager = DesktopProxyRuntimeManager(store, baseDir = store.runtimeDirectory()),
                validationRuntime = DesktopProxyValidationRuntime(baseDir = store.validationDirectory()),
                subscriptionContentFetcher = DesktopSubscriptionDownloadClient(),
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
                subscriptionContentFetcher = subscriptionContentFetcher,
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
        details += "Runtime mode: ${runtimeManager.currentMode()?.let(MainCommandLogic::connectionDisplayName) ?: MainCommandLogic.connectionDisplayName(state.appMode)}"
        runtimeManager.currentPort()?.let { details += "Local proxy: 127.0.0.1:$it" }
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
        details += "Runtime log: $logPath"
        return details
    }

    fun visibleDesktopLocations(): List<DesktopLocationRecord> {
        return desktopLocations.filter { it.rawLink in state.currentLocations }
    }

    fun selectedDesktopLocation(): DesktopLocationRecord? {
        return desktopLocations.firstOrNull { it.rawLink == state.selectedProfileRawLink }
            ?: visibleDesktopLocations().firstOrNull { it.isSelected }
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
            statusPrefix = "Refreshing subscriptions...",
        )
    }

    suspend fun refreshActiveSubscriptions() {
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(state)
        if (refreshTargets.isEmpty()) {
            updateState { it.withStatus("Set a remote source first") }
            return
        }
        refreshDesktopSubscriptions(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = if (refreshTargets.size == 1) {
                "Refreshing subscription..."
            } else {
                "Refreshing subscriptions..."
            },
        )
    }

    suspend fun runAutoRefreshCycle() {
        if (state.isBusy) return
        val refreshTargets = MainCommandLogic.currentSubscriptionSearchTargets(state)
        if (refreshTargets.isEmpty()) return
        val refreshResult = refreshDesktopSubscriptions(
            subscriptionsToRefresh = refreshTargets,
            statusPrefix = if (refreshTargets.size == 1) {
                "Auto-refreshing subscription..."
            } else {
                "Auto-refreshing subscriptions..."
            },
        )
        if (refreshResult.isFailure) return
        if (state.isVpnRunning && state.findBestAfterSubscriptionRefresh) {
            autoRefreshBestSelectionAction(this)
        }
    }

    fun addSampleLocation() {
        val nextIndex = (desktopLocations.maxOfOrNull { it.index } ?: 0) + 1
        val newLocation = DesktopLocationRecord(
            index = nextIndex,
            sourceUrl = "",
            rawLink = "vless://desktop-$nextIndex",
            name = "Desktop Node $nextIndex",
            server = "desktop-$nextIndex.example.net",
            details = "VLESS TCP",
            benchmarkDetail = "primary ok • secondary ok • ${120 + nextIndex} ms",
            isValid = true,
        )
        commitState(
            nextLocations = desktopLocations + newLocation,
            nextState = state.withStatus("Added ${newLocation.name}"),
        )
    }

    fun editLocation(index: Int) {
        val updatedLocations = desktopLocations.map { location ->
            if (location.index == index) {
                location.copy(name = "${location.name} (edited)")
            } else {
                location
            }
        }
        commitState(
            nextLocations = updatedLocations,
            nextState = state.withStatus("Edited location #$index"),
        )
    }

    suspend fun deleteLocation(index: Int) {
        val removed = desktopLocations.firstOrNull { it.index == index } ?: return
        val removedSelected = removed.rawLink == state.selectedProfileRawLink
        if (removedSelected && state.isVpnRunning) {
            val stopResult = stopDesktopProxy(MainCommandLogic.stoppedConnectionLabel(runtimeManager.currentMode() ?: state.appMode))
            if (stopResult.isFailure) {
                return
            }
        }
        val updatedLocations = desktopLocations.filterNot { it.index == index }
        commitState(
            nextLocations = updatedLocations,
            nextState = state.clearSelectedLocationIf(removedSelected)
                .withStatus("Deleted ${removed.name}"),
        )
    }

    fun applyLocationSelection(index: Int, messagePrefix: String = "Selected") {
        val selected = desktopLocations.firstOrNull { it.index == index } ?: return
        val updatedLocations = desktopLocations.map { it.copy(isSelected = it.index == index) }
        commitState(
            nextLocations = updatedLocations,
            nextState = state.withStatus("$messagePrefix ${selected.name}").copy(
                selectedProfileName = selected.name,
                selectedProfileServer = selected.server,
                selectedProfileRawLink = selected.rawLink,
                selectedProfileSourceUrl = selected.sourceUrl,
            ),
        )
    }

    fun setRoutingIgnoreRulesDraft(enabled: Boolean) {
        updateState { it.copy(routingIgnoreRulesDraft = enabled) }
    }

    fun setRoutingAppSearch(query: String) {
        updateState { it.copy(routingAppSearch = query) }
    }

    fun toggleProxyApp(packageName: String) {
        updateState {
            it.copy(
                routingProxyPackagesDraft = if (packageName in it.routingProxyPackagesDraft) {
                    it.routingProxyPackagesDraft - packageName
                } else {
                    it.routingProxyPackagesDraft + packageName
                },
            )
        }
    }

    fun selectAllProxyApps() {
        updateState { it.copy(routingProxyPackagesDraft = it.installedApps.map(InstalledApp::packageName).toSet()) }
    }

    fun clearAllProxyApps() {
        updateState { it.copy(routingProxyPackagesDraft = emptySet()) }
    }

    fun setRoutingNationalDomainsDraft(value: String) {
        updateState { it.copy(routingNationalDomainsDraft = value) }
    }

    fun setRoutingDirectDomainsDraft(value: String) {
        updateState { it.copy(routingDirectDomainsDraft = value) }
    }

    fun addSampleRuleSet() {
        updateState {
            it.withStatus("Added a sample rule-set").copy(
                routingRuleSetsDraft = it.routingRuleSetsDraft + RoutingRuleSet(
                    id = "desktop-${it.routingRuleSetsDraft.size + 1}",
                    name = "Desktop Sample ${it.routingRuleSetsDraft.size + 1}",
                    sourceType = RoutingRuleSetSourceType.INLINE,
                    format = RoutingRuleSetFormat.SOURCE,
                    action = RoutingRuleSetAction.BLOCK,
                    source = """{"version":1,"rules":[{"domain_suffix":["ads.example"]}]}""",
                ),
            )
        }
    }

    fun editRuleSet(id: String) {
        updateState {
            it.copy(
                routingRuleSetsDraft = it.routingRuleSetsDraft.map { ruleSet ->
                    if (ruleSet.id == id) ruleSet.copy(name = "${ruleSet.name} (edited)") else ruleSet
                },
            )
        }
    }

    fun deleteRuleSet(id: String) {
        updateState {
            it.copy(routingRuleSetsDraft = it.routingRuleSetsDraft.filterNot { ruleSet -> ruleSet.id == id })
                .withStatus("Deleted rule-set $id")
        }
    }

    fun saveRoutingRules() {
        updateState {
            it.withStatus("Saved routing rules").copy(
                routingRules = RoutingRules(
                    ignoreRules = it.routingIgnoreRulesDraft,
                    proxyPackages = RoutingRules.normalizePackageNames(it.routingProxyPackagesDraft),
                    bypassPackages = emptyList(),
                    nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(it.routingNationalDomainsDraft),
                    directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(it.routingDirectDomainsDraft),
                    ruleSets = emptyList(),
                ),
            )
        }
    }

    suspend fun stopDesktopProxy(message: String? = null): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtimeManager.isRunning()
        val stoppedMode = runtimeManager.currentMode() ?: state.appMode
        resumeConnectionOnLaunch = false
        if (!wasRunning) {
            commitState(
                nextState = state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionLabel(stoppedMode)),
            )
            return Result.success(Unit)
        }
        updateState { it.copy(isBusy = true) }
        val result = runtimeManager.stop()
        val stoppedAt = System.currentTimeMillis()
        if (result.isSuccess) {
            commitState(
                nextState = state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                    successfulStops = state.successfulStops + 1,
                ).withStatus(message ?: MainCommandLogic.stoppedConnectionLabel(stoppedMode)),
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    result.exceptionOrNull()?.message ?: "Failed to stop ${MainCommandLogic.connectionDisplayName(stoppedMode)}",
                )
            }
        }
        return result.map { Unit }
    }

    private suspend fun stopRuntimeForAppExit(): Result<Unit> {
        val wasRunning = state.isVpnRunning || runtimeManager.isRunning()
        val stoppedMode = runtimeManager.currentMode() ?: state.appMode
        resumeConnectionOnLaunch = wasRunning
        if (!wasRunning) {
            commitState(
                nextState = state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus("App closed. VPN was off."),
            )
            return Result.success(Unit)
        }

        updateState { it.copy(isBusy = true) }
        val result = runtimeManager.stop()
        val stoppedAt = System.currentTimeMillis()
        if (result.isSuccess) {
            commitState(
                nextState = state.copy(
                    isBusy = false,
                    isVpnRunning = false,
                    sessionStoppedAtEpochMillis = stoppedAt,
                ).withStatus("${MainCommandLogic.connectionDisplayName(stoppedMode)} stopped. Will reconnect on next launch."),
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    result.exceptionOrNull()?.message ?: "Failed to stop ${MainCommandLogic.connectionDisplayName(stoppedMode)} before exit",
                )
            }
        }
        return result.map { Unit }
    }

    suspend fun startDesktopProxy(
        location: DesktopLocationRecord,
        benchmarkSummary: String? = null,
    ): Result<Unit> {
        val targetMode = state.appMode
        val profile = runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }
        if (profile.isFailure) {
            val error = profile.exceptionOrNull()?.message ?: "Invalid location config"
            updateState { it.withStatus(error) }
            return Result.failure(IllegalStateException(error))
        }

        val selectedLocations = desktopLocations.map { it.copy(isSelected = it.index == location.index) }
        commitState(
            nextLocations = selectedLocations,
            nextState = state.copy(
                isBusy = true,
                selectedProfileName = location.name,
                selectedProfileServer = location.server,
                selectedProfileRawLink = location.rawLink,
                selectedProfileSourceUrl = location.sourceUrl,
            ).withStatus(MainCommandLogic.startingConnectionLabel(targetMode)),
        )

        val result = runtimeManager.start(
            profile = profile.getOrThrow(),
            routingRules = MainDraftLogic.buildEditedRoutingRules(state),
            dnsSettings = DesktopDnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            ),
            appMode = targetMode,
        )
        if (result.isSuccess) {
            val session = result.getOrThrow()
            val startedAt = System.currentTimeMillis()
            resumeConnectionOnLaunch = true
            val startedMessage = when (targetMode) {
                AppMode.PROXY_ONLY -> "Proxy started on 127.0.0.1:${session.listenPort}"
                AppMode.VPN -> "VPN started on ${session.interfaceName ?: DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME}"
            }
            commitState(
                nextLocations = selectedLocations,
                nextState = state.copy(
                    isBusy = false,
                    isVpnRunning = true,
                    hasVpnPermission = true,
                    sessionStartedAtEpochMillis = startedAt,
                    sessionStoppedAtEpochMillis = 0L,
                    successfulStarts = state.successfulStarts + 1,
                    lastBenchmarkSummary = benchmarkSummary ?: state.lastBenchmarkSummary,
                ).withStatus(startedMessage),
            )
        } else {
            updateState {
                it.copy(
                    isBusy = false,
                    isVpnRunning = false,
                ).withStatus(result.exceptionOrNull()?.message ?: "Failed to start ${MainCommandLogic.connectionDisplayName(targetMode)}")
            }
        }
        return result.map { Unit }
    }

    suspend fun refreshDesktopSubscriptions(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
    ): Result<Int> {
        if (subscriptionsToRefresh.isEmpty()) {
            updateState { it.withStatus("Set a remote source first") }
            return Result.failure(IllegalStateException("No subscriptions to refresh"))
        }

        updateState { it.copy(isBusy = true, isRefreshing = true).withStatus(statusPrefix) }

        val now = System.currentTimeMillis()
        val loadedByUrl = linkedMapOf<String, List<VlessProfile>>()
        val failedLabels = mutableListOf<String>()
        var currentSubscriptions = state.subscriptions

        for (subscription in subscriptionsToRefresh) {
            updateState { it.withStatus("Refreshing ${subscriptionDisplayName(subscription)}...") }
            val result = runCatching {
                loadDesktopSubscriptionProfiles(subscription.url)
            }
            currentSubscriptions = currentSubscriptions.map { source ->
                if (source.id != subscription.id) {
                    source
                } else {
                    result.fold(
                        onSuccess = { profiles ->
                            loadedByUrl[source.url] = profiles
                            source.copy(
                                cachedLocations = profiles.map(LocationConfigs::encodeStoredLocation),
                                lastRefreshedAtEpochMillis = now,
                                lastRefreshStatus = "${profiles.size} locations refreshed",
                            )
                        },
                        onFailure = { error ->
                            failedLabels += subscriptionDisplayName(source)
                            source.copy(
                                lastRefreshedAtEpochMillis = now,
                                lastRefreshStatus = error.message ?: "Refresh failed",
                            )
                        },
                    )
                }
            }
        }

        val successfulUrls = loadedByUrl.keys
        val preservedLocations = desktopLocations.filter { location ->
            location.sourceUrl.isBlank() || location.sourceUrl !in successfulUrls
        }
        val rebuiltLocations = buildList {
            addAll(preservedLocations)
            var nextIndex = nextLocationIndex(preservedLocations)
            loadedByUrl.forEach { (sourceUrl, profiles) ->
                val (mapped, updatedNextIndex) = profilesToDesktopLocations(
                    sourceUrl = sourceUrl,
                    profiles = profiles,
                    existingLocations = desktopLocations,
                    startIndex = nextIndex,
                )
                addAll(mapped)
                nextIndex = updatedNextIndex
            }
        }

        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            rebuiltLocations.none { it.rawLink == state.selectedProfileRawLink }
        if (removedSelected && state.isVpnRunning) {
            val stopResult = stopDesktopProxy("${activeConnectionName()} stopped. Refreshed subscriptions removed the selected location.")
            if (stopResult.isFailure) {
                updateState { it.copy(isBusy = false) }
                return Result.failure(stopResult.exceptionOrNull() ?: IllegalStateException("Failed to stop ${activeConnectionName()}"))
            }
        }

        val summary = MainCommandLogic.formatRefreshSummaryMessage(
            refreshedCount = loadedByUrl.size,
            failedSubscriptions = failedLabels,
            totalCount = subscriptionsToRefresh.size,
            defaultSuccess = if (loadedByUrl.size == 1 && subscriptionsToRefresh.size == 1) {
                "Subscription refreshed"
            } else {
                "Subscriptions refreshed"
            },
        )
        commitState(
            nextLocations = rebuiltLocations,
            nextState = state.clearSelectedLocationIf(removedSelected)
                .copy(
                    isBusy = false,
                    isRefreshing = false,
                    subscriptions = currentSubscriptions,
                )
                .withStatus(summary),
        )
        return Result.success(loadedByUrl.size)
    }

    suspend fun importLocationsRaw(raw: String) {
        when (val decision = LocationMutationLogic.planImportLocations(state, raw)) {
            is com.kardinal.vpncontrol.ImportLocationsDecision.Blocked -> {
                updateState { it.withStatus(decision.message) }
            }
            is com.kardinal.vpncontrol.ImportLocationsDecision.Invalid -> {
                updateState { it.withStatus(decision.message) }
            }
            is com.kardinal.vpncontrol.ImportLocationsDecision.Plan -> {
                val preservedSubscriptionLocations = desktopLocations.filter { it.sourceUrl.isNotBlank() }
                val importedLocations = decision.importedLocations.toDesktopLocationRecords(
                    startIndex = nextLocationIndex(preservedSubscriptionLocations),
                )
                val nextLocations = preservedSubscriptionLocations + importedLocations
                val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
                    nextLocations.none { it.rawLink == state.selectedProfileRawLink }
                if (removedSelected && state.isVpnRunning) {
                    val stopResult = stopDesktopProxy(
                        LocationMutationLogic.importLocationsStoppedStatusMessage(state.appMode),
                    )
                    if (stopResult.isFailure) {
                        return
                    }
                }
                val message = if (removedSelected && state.isVpnRunning) {
                    LocationMutationLogic.importLocationsStoppedStatusMessage(state.appMode)
                } else {
                    LocationMutationLogic.importLocationsStatusMessage(removedSelected)
                }
                commitState(
                    nextLocations = nextLocations,
                    nextState = state.clearSelectedLocationIf(removedSelected)
                        .copy(isVpnRunning = if (removedSelected) false else state.isVpnRunning)
                        .withStatus(message),
                )
            }
        }
    }

    suspend fun importLocationsFromClipboard() {
        val raw = DesktopTextTransfer.readClipboardText()
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: "Clipboard read failed") }
            return
        }
        importLocationsRaw(raw.getOrThrow())
    }

    suspend fun importLocationsFromFile(selection: Result<Path?>) {
        if (selection.isFailure) {
            updateState { it.withStatus(selection.exceptionOrNull()?.message ?: "Failed to open locations file") }
            return
        }
        val path = selection.getOrNull() ?: return
        val raw = DesktopTextTransfer.readTextFile(path)
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: "Failed to read locations file") }
            return
        }
        importLocationsRaw(raw.getOrThrow())
    }

    fun exportLocationsToClipboard() {
        if (state.currentLocations.isEmpty()) {
            updateState { it.withStatus("No locations to export") }
            return
        }
        val document = LocationConfigs.export(state.currentLocations)
        val result = DesktopTextTransfer.writeClipboardText(document.content)
        updateState {
            it.withStatus(
                result.exceptionOrNull()?.message ?: "Locations copied to clipboard",
            )
        }
    }

    fun exportLocationsToFile(window: ComposeWindow) {
        if (state.currentLocations.isEmpty()) {
            updateState { it.withStatus("No locations to export") }
            return
        }
        val document = LocationConfigs.export(state.currentLocations)
        val result = DesktopTextTransfer.saveTextFile(
            window = window,
            title = "Export Locations",
            suggestedFileName = document.fileName,
            content = document.content,
        )
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path ->
                        if (path == null) {
                            "Locations export canceled"
                        } else {
                            "Locations exported to $path"
                        }
                    },
                    onFailure = { error -> error.message ?: "Failed to export locations" },
                ),
            )
        }
    }

    fun importRoutingRulesRaw(raw: String) {
        val parsed = runCatching { RoutingRulesTransfer.import(raw) }
        if (parsed.isFailure) {
            updateState { it.withStatus(parsed.exceptionOrNull()?.message ?: "Failed to import routing rules") }
            return
        }
        val rules = MainDraftLogic.sanitizeRoutingRules(parsed.getOrThrow())
        val message = if (state.isVpnRunning) {
            "Routing rules imported. Restart ${MainCommandLogic.connectionNoun(state.appMode)} to apply"
        } else {
            "Routing rules imported"
        }
        commitState(
            nextState = MainDraftLogic.applyImportedRoutingRules(
                state.copy(routingRules = rules),
                rules,
            ).withStatus(message),
        )
    }

    fun importRoutingRulesFromClipboard() {
        val raw = DesktopTextTransfer.readClipboardText()
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: "Clipboard read failed") }
            return
        }
        importRoutingRulesRaw(raw.getOrThrow())
    }

    fun importRoutingRulesFromFile(window: ComposeWindow) {
        val opened = DesktopTextTransfer.openTextFile(window, "Import Routing Rules")
        if (opened.isFailure) {
            updateState { it.withStatus(opened.exceptionOrNull()?.message ?: "Failed to open routing rules file") }
            return
        }
        val raw = opened.getOrNull() ?: return
        importRoutingRulesRaw(raw)
    }

    fun exportRoutingRulesToClipboard() {
        val document = RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(state))
        val result = DesktopTextTransfer.writeClipboardText(document.content)
        updateState {
            it.withStatus(
                result.exceptionOrNull()?.message ?: "Routing rules copied to clipboard",
            )
        }
    }

    fun exportRoutingRulesToFile(window: ComposeWindow) {
        val document = RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(state))
        val result = DesktopTextTransfer.saveTextFile(
            window = window,
            title = "Export Routing Rules",
            suggestedFileName = document.fileName,
            content = document.content,
        )
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path ->
                        if (path == null) {
                            "Routing rules export canceled"
                        } else {
                            "Routing rules exported to $path"
                        }
                    },
                    onFailure = { error -> error.message ?: "Failed to export routing rules" },
                ),
            )
        }
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
            logFile = runtimeManager.currentLogFile() ?: runtimeManager.defaultLogFile(),
            runtimeConfigJson = desktopStore.readRuntimeConfig() ?: runtimeManager.lastAttemptedConfigJson(),
            preflightReport = runtimeManager.lastPreflightReport(),
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
                statusPrefix = if (refreshTargets.size == 1) {
                    "Refreshing subscription..."
                } else {
                    "Refreshing subscriptions..."
                },
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
        val evaluation = validationRuntime.evaluateProfiles(
            profiles = profiles,
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
        return MainCommandLogic.connectionDisplayName(runtimeManager.currentMode() ?: state.appMode)
    }

    private fun subscriptionDisplayName(subscription: SubscriptionSource): String {
        return subscription.customName.ifBlank {
            displayRemoteSourceHost(subscription.url) ?: "Subscription"
        }
    }

    private suspend fun loadDesktopSubscriptionProfiles(rawSource: String): List<VlessProfile> {
        return SelectionWorkflowService.parseRemoteSourceLocations(
            rawSource = rawSource,
            resolveSource = { source ->
                when (val parsed = parseDirectRemoteSource(source)) {
                    is DirectRemoteSourceResolution -> ResolvedRemoteSource(
                        preview = parsed.preview,
                        fetchUrl = parsed.url,
                    )
                    is UnsupportedRemoteSourceResolution -> error(parsed.errorMessage)
                    null -> error("Remote source must be a valid https:// URL")
                }
            },
            fetchedContent = subscriptionContentFetcher::fetch,
        )
    }

    private fun profilesToDesktopLocations(
        sourceUrl: String,
        profiles: List<VlessProfile>,
        existingLocations: List<DesktopLocationRecord>,
        startIndex: Int,
    ): Pair<List<DesktopLocationRecord>, Int> {
        val existingByKey = existingLocations
            .filter { it.sourceUrl == sourceUrl }
            .associateBy { it.normalizedStorageKey() }
        var nextIndex = startIndex
        val mapped = profiles.map { profile ->
            val rawLink = LocationConfigs.encodeStoredLocation(profile)
            val existing = existingByKey[LocationConfigs.normalizeStoredReference(rawLink)]
            DesktopLocationRecord(
                index = existing?.index ?: nextIndex++,
                sourceUrl = sourceUrl,
                rawLink = rawLink,
                name = profile.remarks,
                server = profile.server,
                details = profile.desktopDetails(),
                benchmarkDetail = existing?.benchmarkDetail ?: "Refreshed • not checked yet",
                isValid = existing?.isValid ?: true,
                isSelected = existing?.isSelected ?: false,
            )
        }
        return mapped to nextIndex
    }

    private fun updateLocationBenchmarks(
        detailsByRawKey: Map<String, String>,
        winningRawKey: String? = null,
    ) {
        if (detailsByRawKey.isEmpty()) return
        val updatedLocations = desktopLocations.map { location ->
            val normalized = location.normalizedStorageKey()
            val detail = detailsByRawKey[normalized] ?: return@map location
            val isHealthy = detail.contains("primary=ok")
            location.copy(
                benchmarkDetail = detail.toCompactBenchmarkLabel(),
                isValid = isHealthy,
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
    val now = System.currentTimeMillis()
    val subscriptions = defaultSubscriptions()
    val locations = defaultDesktopLocations()
    val persisted = PersistedState(
        profileUrl = subscriptions.first().url,
        activeSubscriptionId = subscriptions.first().id,
        subscriptions = subscriptions,
        profileHistory = subscriptions.map(SubscriptionSource::url),
        profileHistoryNames = subscriptions
            .filter { it.customName.isNotBlank() }
            .associate { it.url to it.customName },
        profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
        appMode = AppMode.VPN,
        subscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
        findBestAfterSubscriptionRefresh = true,
        subscriptionRefreshCustomHours = 0.5,
        currentLocations = locations.map(DesktopLocationRecord::rawLink),
        savedLocations = locations.map(DesktopLocationRecord::rawLink),
        locationBenchmarkDetails = locations.associate { it.rawLink to it.benchmarkDetail },
        routingRules = RoutingRules(),
        selectedProfileName = "Netherlands",
        selectedProfileServer = "nl.example.net",
        selectedProfileRawLink = "vless://desktop-nl",
        selectedProfileSourceUrl = subscriptions.first().url,
        lastBenchmarkSummary = "Desktop shell: Netherlands from Whitelists",
        statusMessage = "Desktop VPN shell ready",
        isVpnRunning = false,
        successfulStarts = 0,
        successfulStops = 0,
        connectionLog = listOf(
            ConnectionLogEntry(
                id = "desktop-log-1",
                message = "Desktop shell initialized",
                createdAtEpochMillis = now - 10 * 60_000L,
            ),
            ConnectionLogEntry(
                id = "desktop-log-2",
                message = "Selected Netherlands from Whitelists",
                createdAtEpochMillis = now - 7 * 60_000L,
            ),
            ConnectionLogEntry(
                id = "desktop-log-3",
                message = "VPN mode available",
                createdAtEpochMillis = now - 6 * 60_000L,
            ),
        ),
    )
    return DesktopWorkspace(
        persistedState = persisted,
        locations = locations,
    )
}

private fun restoreDesktopUiState(
    persistedState: PersistedState,
    locations: List<DesktopLocationRecord>,
): MainUiState {
    val base = MainUiStateProjector.mergePersistedState(
        current = MainUiState(
            currentScreen = AppScreen.MAIN,
            installedApps = sampleInstalledApps(),
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
            installedApps = sampleInstalledApps(),
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

private fun defaultSubscriptions(): List<SubscriptionSource> {
    val now = System.currentTimeMillis()
    return listOf(
        SubscriptionSource(
            id = "desktop-sub-1",
            url = "https://desktop.example.net/whitelists",
            customName = "Whitelists",
            cachedLocations = listOf("vless://desktop-nl", "trojan://desktop-de"),
            lastRefreshedAtEpochMillis = now - 30 * 60_000L,
            lastRefreshStatus = "2 locations refreshed",
        ),
        SubscriptionSource(
            id = "desktop-sub-2",
            url = "https://desktop.example.net/fallback",
            customName = "Fallback",
            cachedLocations = listOf("vless://desktop-us"),
            lastRefreshedAtEpochMillis = now - 75 * 60_000L,
            lastRefreshStatus = "1 location refreshed",
        ),
    )
}

private fun sampleInstalledApps(): List<InstalledApp> {
    return listOf(
        InstalledApp(packageName = "com.example.browser", label = "Browser", isSystemApp = false),
        InstalledApp(packageName = "org.telegram.messenger", label = "Telegram", isSystemApp = false),
        InstalledApp(packageName = "com.spotify.music", label = "Spotify", isSystemApp = false),
        InstalledApp(packageName = "com.android.settings", label = "Settings", isSystemApp = true),
    )
}

private fun defaultDesktopLocations(): List<DesktopLocationRecord> {
    return listOf(
        DesktopLocationRecord(
            index = 0,
            sourceUrl = "https://desktop.example.net/whitelists",
            rawLink = "vless://desktop-nl",
            name = "Netherlands",
            server = "nl.example.net",
            details = "VLESS Reality",
            benchmarkDetail = "primary ok • secondary ok • 118 ms",
            isValid = true,
            isSelected = true,
        ),
        DesktopLocationRecord(
            index = 1,
            sourceUrl = "https://desktop.example.net/whitelists",
            rawLink = "trojan://desktop-de",
            name = "Germany",
            server = "de.example.net",
            details = "Trojan TLS",
            benchmarkDetail = "primary ok • secondary ok • 132 ms",
            isValid = true,
        ),
        DesktopLocationRecord(
            index = 2,
            sourceUrl = "https://desktop.example.net/fallback",
            rawLink = "vless://desktop-us",
            name = "United States",
            server = "us.example.net",
            details = "VLESS WS",
            benchmarkDetail = "primary ok • secondary timeout • 188 ms",
            isValid = true,
        ),
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
    val selectedLocation = state.selectedProfileRawLink
        .takeIf(String::isNotBlank)
        ?.let { rawLink -> locations.firstOrNull { it.rawLink == rawLink } }
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

private fun MainUiState.clearSelectedLocationIf(shouldClear: Boolean): MainUiState {
    if (!shouldClear) return this
    return copy(
        selectedProfileName = "",
        selectedProfileServer = "",
        selectedProfileRawLink = "",
        selectedProfileSourceUrl = "",
    )
}

private fun List<String>.toDesktopLocationRecords(startIndex: Int): List<DesktopLocationRecord> {
    return mapIndexed { offset, rawLink ->
        val profile = LocationConfigs.decodeStoredLocation(rawLink)
        DesktopLocationRecord(
            index = startIndex + offset,
            sourceUrl = "",
            rawLink = rawLink,
            name = profile.remarks,
            server = profile.server,
            details = profile.desktopDetails(),
            benchmarkDetail = "Imported • not checked yet",
            isValid = true,
        )
    }
}

private fun DesktopLocationRecord.normalizedStorageKey(): String {
    return LocationConfigs.normalizeStoredReference(rawLink)
}

private fun nextLocationIndex(locations: List<DesktopLocationRecord>): Int {
    return (locations.maxOfOrNull(DesktopLocationRecord::index) ?: -1) + 1
}

private fun VlessProfile.desktopDetails(): String {
    val protocolLabel = when (protocol) {
        ProxyProtocol.VLESS -> "VLESS"
        ProxyProtocol.TROJAN -> "Trojan"
        ProxyProtocol.SHADOWSOCKS -> "Shadowsocks"
        ProxyProtocol.VMESS -> "VMess"
        ProxyProtocol.SOCKS -> "SOCKS"
        ProxyProtocol.CUSTOM -> "Custom"
    }
    val tags = buildList {
        security.takeIf { it.isNotBlank() && !it.equals("none", ignoreCase = true) }?.let {
            add(it.uppercase())
        }
        network.takeIf { it.isNotBlank() && !it.equals("tcp", ignoreCase = true) }?.let {
            add(it.uppercase())
        }
        if (protocol == ProxyProtocol.SHADOWSOCKS) {
            method.takeIf { it.isNotBlank() }?.let(::add)
        }
    }
    return (listOf(protocolLabel) + tags)
        .joinToString(" ")
        .trim()
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

private fun MainUiState.withStatus(message: String): MainUiState {
    val now = System.currentTimeMillis()
    return copy(
        statusMessage = message,
        connectionLog = (connectionLog + ConnectionLogEntry(
            id = "desktop-$now-${connectionLog.size}",
            message = message,
            createdAtEpochMillis = now,
        )).takeLast(50),
    )
}
