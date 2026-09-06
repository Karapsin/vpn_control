package com.kardinal.vpncontrol

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.kardinal.vpncontrol.data.DiagnosticsLogger
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

class MainViewModel internal constructor(
    private val appContext: Context,
    private val owner: AndroidApplicationOwner,
) : ViewModel() {
    private val repository = owner.repository
    private val vpnManager = owner.vpnManager
    private val diagnosticsExporter = owner.diagnosticsExporter
    private val installedAppsCatalog = owner.installedAppsCatalog
    private val commands = owner.commands
    private val controller = MainController()
    private val _uiState = controller.mutableState
    val uiState: StateFlow<MainUiState> = controller.state
    internal val runtimeObservation = owner.runtimeObserver.state
    private val mutableLocationVisualState = kotlinx.coroutines.flow.MutableStateFlow(AndroidLocationVisualState())
    val locationVisualState: kotlinx.coroutines.flow.StateFlow<AndroidLocationVisualState> = mutableLocationVisualState
    private val installedAppsActions = AndroidInstalledAppsActionsService(
        stateProvider = { _uiState.value },
        updateState = { transform -> _uiState.value = transform(_uiState.value) },
        launch = commands::launch,
        loadInstalledApps = installedAppsCatalog::load,
        updateStatus = repository::updateStatus,
    )
    private val controllerEffectHandler: AndroidControllerEffectHandler = AndroidControllerEffectHandler(
        repository = repository,
        launch = commands::launch,
        ensureInstalledAppsLoaded = installedAppsActions::ensureLoaded,
        importRoutingRules = { routingActions.importRoutingRulesWithinMutation(it) },
        launchMutation = ::launchMutationOrReportBusy,
    )
    private val profileActions = AndroidProfileActionsService(
        controller = controller,
        stateProvider = { _uiState.value },
        effectSink = controllerEffectHandler,
        launch = commands::launch,
        updateStatus = repository::updateStatus,
        launchMutation = ::launchMutationOrReportBusy,
    )
    private val connectionLifecycle = AndroidConnectionLifecycleService(
        stateProvider = { _uiState.value },
        updateState = { transform -> _uiState.value = transform(_uiState.value) },
        setBusy = ::setBusy,
        updateStatus = repository::updateStatus,
        snapshot = repository::snapshot,
        restoreSnapshot = { state, restoreRuntimeArtifacts ->
            repository.restoreSnapshot(state, restoreRuntimeArtifacts = restoreRuntimeArtifacts)
        },
        ensureSelection = repository::ensureSelection,
        persistSelection = { selection -> repository.persistSelection(selection) },
        rehydrateSelection = repository::rehydrateSelection,
        startConnection = { selection -> vpnManager.start(selection) },
        stopConnection = vpnManager::stop,
    )
    private val connectionActions = AndroidConnectionActionsService(
        controller = controller,
        connectionLifecycle = connectionLifecycle,
        launchTrackedBusyOperation = ::launchTrackedBusyOperation,
    )
    private val locationActions = AndroidLocationActionsService(
        guarded = AndroidGuiLocationActions(controller, { _uiState.value }, commands::launch,
            owner.storage::configurationSnapshot, owner.settingsControl::execute),
        controller = controller,
        stateProvider = { _uiState.value },
        launch = commands::launch,
        launchTrackedBusyOperation = ::launchTrackedBusyOperation,
        launchMutation = { commands.launchMutation(it) },
        setBusy = ::setBusy,
        setRefreshing = { value -> _uiState.value = _uiState.value.copy(isRefreshing = value) },
        updateStatus = repository::updateStatus,
        snapshot = repository::snapshot,
        restoreSnapshot = { state -> repository.restoreSnapshot(state) },
        updateCurrentLocations = repository::updateCurrentLocations,
        selectionFromRawLink = repository::selectionFromRawLink,
        applyAndPersistSelection = connectionLifecycle::applyAndPersistSelection,
        rollbackSelectionChange = connectionLifecycle::rollbackSelectionChange,
        stopConnection = vpnManager::stop,
        benchmarkLocation = repository::benchmarkLocation,
        appendLatencyHistory = repository::appendLatencyHistory,
    )
    private val routingActions: AndroidRoutingActionsService = AndroidRoutingActionsService(
        controller = controller,
        stateProvider = { _uiState.value },
        effectSink = controllerEffectHandler,
        launch = ::launchMutationOrReportBusy,
        setBusy = ::setBusy,
        updateRoutingRules = repository::updateRoutingRules,
        updateStatus = repository::updateStatus,
    )
    private val subscriptionRefreshActions = AndroidSubscriptionRefreshActionsService(
        stateProvider = { _uiState.value },
        launch = { commands.launchMutation(it) },
        setBusy = ::setBusy,
        updateStatus = repository::updateStatus,
        runActiveRefresh = repository::refreshActiveSubscriptionCache,
        runSubscriptionRefresh = repository::refreshSubscriptionCache,
        runAllRefresh = repository::refreshAllSubscriptionsCaches,
    )
    private val findBestActions = AndroidFindBestActionsService(
        stateProvider = { _uiState.value },
        launchTrackedBusyOperation = ::launchTrackedBusyOperation,
        setBusy = ::setBusy,
        setRefreshing = { value -> _uiState.value = _uiState.value.copy(isRefreshing = value) },
        updateStatus = repository::updateStatus,
        snapshot = repository::snapshot,
        restoreSnapshot = { state -> repository.restoreSnapshot(state) },
        refreshBestProfileAttemptPlan = repository::refreshBestProfileAttemptPlan,
        startSelection = connectionLifecycle::startSelection,
        persistSelection = repository::persistSelection,
        verifyActiveSelection = repository::verifyActiveSelection,
        verifySelectionCandidate = repository::verifySelectionCandidate,
        rollbackSelectionChange = connectionLifecycle::rollbackSelectionChange,
        stopConnection = vpnManager::stop,
        updateLocationBenchmarkDetails = repository::updateLocationBenchmarkDetails,
        appendLatencyHistory = repository::appendLatencyHistory,
        diagnosticsLogger = { message -> DiagnosticsLogger.append(appContext, message) },
    )
    private val settingsActions = AndroidSettingsActionsService(
        controller = controller,
        effectSink = controllerEffectHandler,
        launch = commands::launch,
        stopConnection = vpnManager::stop,
        updateStatus = repository::updateStatus,
        updateSessionStatsEnabled = repository::updateSessionStatsEnabled,
        updateLiveTrafficStatsEnabled = repository::updateLiveTrafficStatsEnabled,
        updateProfileTotalsEnabled = repository::updateProfileTotalsEnabled,
        updateLatencyHistoryEnabled = repository::updateLatencyHistoryEnabled,
        updateConnectionLogEnabled = repository::updateConnectionLogEnabled,
        updateConnectionTestToolsEnabled = repository::updateConnectionTestToolsEnabled,
        credentialStore = com.kardinal.vpncontrol.data.AndroidHomeSshCredentialStore(appContext),
        updateHomeSshRouteSettings = repository::updateHomeSshRouteSettings,
        launchMutation = ::launchMutationOrReportBusy,
        importKey = owner::importSshKey,
        homeSshPendingRestart = owner::pendingRestartAfterSettingsSave,
    )
    private val diagnosticsActions = AndroidDiagnosticsActionsService(
        launch = commands::launch,
        setBusy = ::setBusy,
        updateStatus = repository::updateStatus,
        exportAndShare = diagnosticsExporter::exportAndShare,
    )
    private val updateActions = owner.updateActions

    init {
        repository.state.combine(runtimeObservation) { persisted, observation -> persisted to observation }.onEach { (persisted, observation) ->
            controller.mergePersistedState(persisted)
            _uiState.value = observation.applyKnownState(_uiState.value)
            mutableLocationVisualState.value = owner.runtimeObserver.locationVisualState(persisted)
        }.launchIn(viewModelScope)

        commands.busy.onEach { busy ->
            _uiState.value = _uiState.value.copy(isBusy = busy)
        }.launchIn(viewModelScope)
        owner.updateState.onEach { update ->
            _uiState.value = _uiState.value.copy(appUpdate = update)
        }.launchIn(viewModelScope)
    }

    fun toggleDnsDialog() {
        settingsActions.toggleDnsDialog()
    }

    fun toggleHomeSshRouteDialog() = settingsActions.toggleHomeSshRouteDialog()

    fun setHomeSshEnabledDraft(value: Boolean) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshEnabledDraft = value)
    }

    fun setHomeSshHostDraft(value: String) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshHostDraft = value.take(255))
    }

    fun setHomeSshPortDraft(value: String) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshPortDraft = value.filter(Char::isDigit).take(5))
    }

    fun setHomeSshUserDraft(value: String) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshUserDraft = value.take(128))
    }

    fun setHomeSshHostKeysDraft(value: String) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshHostKeysDraft = value.take(8192))
    }

    fun setHomeSshRelayPortDraft(value: String) = settingsActions.updateHomeSshDraft {
        it.copy(homeSshRelayPortDraft = value.filter(Char::isDigit).take(5))
    }

    fun importHomeSshPrivateKey(content: String) = settingsActions.importHomeSshPrivateKey(content)

    fun saveHomeSshRoute() = settingsActions.saveHomeSshRoute()

    fun dismissHomeSshRestartDialog() = settingsActions.dismissHomeSshRestartDialog()

    fun restartForHomeSshSettings() {
        launchTrackedBusyOperation {
            val state = repository.snapshot()
            val selection = repository.rehydrateSelection(state).getOrThrow()
            val result = connectionLifecycle.reapplyConnectionIfRunning(
                selection = selection,
                statusMessage = com.kardinal.vpncontrol.model.SettingsStatusMessages.homeSshRouteRestarting(),
            )
            result.getOrThrow()
            repository.persistSelection(selection)
            settingsActions.markHomeSshRestartApplied()
        }
    }

    fun toggleUiSettingsDialog() {
        settingsActions.toggleUiSettingsDialog()
    }

    fun setSessionStatsEnabled(enabled: Boolean) {
        settingsActions.setSessionStatsEnabled(enabled)
    }

    fun setLiveTrafficStatsEnabled(enabled: Boolean) {
        settingsActions.setLiveTrafficStatsEnabled(enabled)
    }

    fun setProfileTotalsEnabled(enabled: Boolean) {
        settingsActions.setProfileTotalsEnabled(enabled)
    }

    fun setLatencyHistoryEnabled(enabled: Boolean) {
        settingsActions.setLatencyHistoryEnabled(enabled)
    }

    fun setConnectionLogEnabled(enabled: Boolean) {
        settingsActions.setConnectionLogEnabled(enabled)
    }

    fun setConnectionTestToolsEnabled(enabled: Boolean) {
        settingsActions.setConnectionTestToolsEnabled(enabled)
    }

    fun toggleAppModeDialog() {
        settingsActions.toggleAppModeDialog()
    }

    fun toggleRefreshPolicyDialog() {
        settingsActions.toggleRefreshPolicyDialog()
    }

    fun toggleValidationSettingsDialog() {
        settingsActions.toggleValidationSettingsDialog()
    }

    fun toggleLanguageDialog() {
        settingsActions.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        settingsActions.setAppLanguage(language)
    }

    fun checkAndDownloadUpdate() {
        owner.checkAndDownloadUpdate()
    }

    fun dismissOrCancelUpdate() {
        owner.dismissOrCancelUpdate()
    }

    fun installUpdate(launch: (android.content.Intent) -> Unit) = owner.installUpdate(launch)

    fun openRoutingRules() {
        handleControllerEffects(controller.openRoutingRules())
    }

    fun openMainTab() {
        controller.openMainTab()
    }

    fun openProfileTab() {
        controller.openProfileTab()
    }

    fun openLocationsTab() {
        controller.openLocationsTab()
    }

    fun openStatsTab() {
        controller.openStatsTab()
    }

    fun navigateBack() {
        handleControllerEffects(controller.navigateBack())
    }

    fun onProfileDraftChanged(value: String) {
        profileActions.onProfileDraftChanged(value)
    }

    fun onProfileTitleDraftChanged(value: String) {
        profileActions.onProfileTitleDraftChanged(value)
    }

    fun pasteSubscriptionDraft(raw: String) {
        profileActions.pasteSubscriptionDraft(raw)
    }

    fun toggleAddSubscriptionEditor() {
        profileActions.toggleAddSubscriptionEditor()
    }

    fun showProfileHistoryRenameDialog(source: String) {
        profileActions.showProfileHistoryRenameDialog(source)
    }

    fun closeProfileHistoryRenameDialog() {
        profileActions.closeProfileHistoryRenameDialog()
    }

    fun onProfileHistoryRenameDraftChanged(value: String) {
        profileActions.onProfileHistoryRenameDraftChanged(value)
    }

    fun onProfileHistoryRenameUrlDraftChanged(value: String) {
        profileActions.onProfileHistoryRenameUrlDraftChanged(value)
    }

    fun setProfileSourceMode(value: ProfileSourceMode) {
        profileActions.setProfileSourceMode(value)
    }

    fun setAppMode(value: AppMode) {
        settingsActions.setAppMode(value)
    }

    fun onDnsDraftChanged(value: String) {
        settingsActions.onDnsDraftChanged(value)
    }

    fun onDnsModeChanged(mode: com.kardinal.vpncontrol.model.DnsMode) {
        settingsActions.onDnsModeChanged(mode)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        settingsActions.onSubscriptionRefreshPolicyDraftChanged(policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        settingsActions.onFindBestAfterSubscriptionRefreshDraftChanged(enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        settingsActions.onSubscriptionRefreshCustomHoursDraftChanged(value)
    }

    fun onValidationTestUrlDraftChanged(value: String) {
        settingsActions.onValidationTestUrlDraftChanged(value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        settingsActions.onValidationBatchSizeDraftChanged(value)
    }

    fun onValidationSubscriptionRefreshConcurrencyDraftChanged(value: String) {
        settingsActions.onValidationSubscriptionRefreshConcurrencyDraftChanged(value)
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        settingsActions.onValidationRetryCountDraftChanged(value)
    }

    fun onValidationActiveVerificationWindowSizeDraftChanged(value: String) {
        settingsActions.onValidationActiveVerificationWindowSizeDraftChanged(value)
    }

    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        routingActions.onRoutingIgnoreRulesDraftChanged(enabled)
    }

    fun onRoutingBlockQuicUdp443DraftChanged(enabled: Boolean) {
        routingActions.onRoutingBlockQuicUdp443DraftChanged(enabled)
    }

    fun onRoutingAppSearchChanged(value: String) {
        routingActions.onRoutingAppSearchChanged(value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        routingActions.onRoutingDirectDomainsDraftChanged(value)
    }

    fun showAddRuleSetDialog() {
        routingActions.showAddRuleSetDialog()
    }

    fun editRuleSet(id: String) {
        routingActions.editRuleSet(id)
    }

    fun closeRuleSetDialog() {
        routingActions.closeRuleSetDialog()
    }

    fun onRuleSetNameDraftChanged(value: String) {
        routingActions.onRuleSetNameDraftChanged(value)
    }

    fun onRuleSetSourceDraftChanged(value: String) {
        routingActions.onRuleSetSourceDraftChanged(value)
    }

    fun onRuleSetSourceTypeDraftChanged(value: RoutingRuleSetSourceType) {
        routingActions.onRuleSetSourceTypeDraftChanged(value)
    }

    fun onRuleSetFormatDraftChanged(value: RoutingRuleSetFormat) {
        routingActions.onRuleSetFormatDraftChanged(value)
    }

    fun onRuleSetActionDraftChanged(value: RoutingRuleSetAction) {
        routingActions.onRuleSetActionDraftChanged(value)
    }

    fun onRuleSetUpdateHoursDraftChanged(value: String) {
        routingActions.onRuleSetUpdateHoursDraftChanged(value)
    }

    fun saveRuleSet() {
        routingActions.saveRuleSet()
    }

    fun deleteRuleSet(id: String) {
        routingActions.deleteRuleSet(id)
    }

    fun showAddLocationDialog() {
        locationActions.showAddLocationDialog()
    }

    fun editLocation(index: Int) {
        locationActions.editLocation(index)
    }

    fun closeLocationDialog() {
        locationActions.closeLocationDialog()
    }

    fun closeLocationMutationBlockedDialog() {
        locationActions.closeLocationMutationBlockedDialog()
    }

    fun onLocationDraftChanged(value: String) {
        locationActions.onLocationDraftChanged(value)
    }

    fun toggleProxyRoutingApp(packageName: String) {
        routingActions.toggleProxyRoutingApp(packageName)
    }

    fun toggleDirectRoutingApp(packageName: String) {
        routingActions.toggleDirectRoutingApp(packageName)
    }

    fun selectAllVisibleProxyApps() {
        routingActions.selectAllVisibleProxyApps()
    }

    fun clearAllVisibleProxyApps() {
        routingActions.clearAllVisibleProxyApps()
    }

    fun selectAllVisibleDirectApps() {
        routingActions.selectAllVisibleDirectApps()
    }

    fun clearAllVisibleDirectApps() {
        routingActions.clearAllVisibleDirectApps()
    }

    fun onVpnPermissionGranted() {
        connectionActions.onVpnPermissionGranted()
    }

    fun saveProfile() {
        profileActions.saveProfile()
    }

    fun clearProfileSource() {
        profileActions.clearProfileSource()
    }

    fun refreshActiveSubscriptionCache() {
        subscriptionRefreshActions.refreshActiveSubscriptionCache()
    }

    fun refreshSubscriptionCache(subscriptionId: String) {
        subscriptionRefreshActions.refreshSubscriptionCache(subscriptionId)
    }

    fun refreshAllSubscriptionsCaches() {
        subscriptionRefreshActions.refreshAllSubscriptionsCaches()
    }

    fun handleIncomingSharedText(raw: String) {
        profileActions.handleIncomingSharedText(raw)
    }

    fun handleIncomingImportText(raw: String, preference: ImportPreference = ImportPreference.AUTO) {
        profileActions.handleIncomingImportText(raw, preference)
    }

    fun useProfileHistoryEntry(subscriptionId: String) {
        profileActions.useProfileHistoryEntry(subscriptionId)
    }

    fun deleteProfileHistoryEntry(source: String) {
        profileActions.deleteProfileHistoryEntry(source)
    }

    fun saveProfileHistoryRename() {
        profileActions.saveProfileHistoryRename()
    }

    fun saveSubscriptionRefreshPolicy() {
        settingsActions.saveSubscriptionRefreshPolicy()
    }

    fun saveValidationSettings() {
        settingsActions.saveValidationSettings()
    }

    fun saveLocation() {
        locationActions.saveLocation()
    }

    fun deleteLocation(index: Int) {
        locationActions.deleteLocation(index)
    }
    fun deleteLocation(raw: String) { locationActions.deleteLocation(raw) }
    fun deleteLocation(target: AndroidRenderedLocationTarget) { locationActions.deleteLocation(target) }
    fun editLocation(target: AndroidRenderedLocationTarget) { locationActions.editLocation(target) }
    fun selectLocation(target: AndroidRenderedLocationTarget) { locationActions.selectLocation(target) }

    fun benchmarkLocation(index: Int) {
        locationActions.benchmarkLocation(index)
    }

    fun benchmarkSelectedLocationFromStats() {
        locationActions.benchmarkSelectedLocationFromStats()
    }

    fun selectLocation(index: Int) {
        locationActions.selectLocation(index)
    }

    fun saveDns() {
        settingsActions.saveDns()
    }

    fun saveRoutingRules() {
        routingActions.saveRoutingRules()
    }

    fun buildRoutingRulesExport(): RoutingRulesExportDocument {
        return routingActions.buildRoutingRulesExport()
    }

    fun buildLocationsExport(): LocationsExportDocument {
        return locationActions.buildLocationsExport()
    }

    fun importLocations(raw: String) {
        locationActions.importLocations(raw)
    }
    fun beginImportLocations(openPicker: () -> Unit) = locationActions.beginImportLocations(openPicker)
    fun cancelImportLocations() = locationActions.cancelImportLocations()

    fun importRoutingRules(raw: String) {
        routingActions.importRoutingRules(raw)
    }

    fun postStatus(message: String) {
        settingsActions.postStatus(message)
    }

    fun cancelActiveOperation() {
        commands.cancelActive()
    }

    fun refresh() {
        findBestActions.refresh()
    }

    fun toggleVpn() {
        connectionActions.toggleVpn()
    }

    fun exportDiagnostics() {
        diagnosticsActions.exportDiagnostics()
    }

    private fun handleControllerEffects(effects: List<MainControllerEffect>) {
        controllerEffectHandler.handle(effects)
    }

    private fun setBusy(value: Boolean) {
        commands.setBusy(value)
        _uiState.value = _uiState.value.copy(isBusy = commands.busy.value)
    }

    private fun launchTrackedBusyOperation(block: suspend () -> Unit) {
        commands.launchTracked(block)
    }

    private fun launchMutationOrReportBusy(block: suspend () -> Unit) {
        if (commands.launchMutation(block) == null) {
            commands.launch { repository.updateStatus("BUSY") }
        }
    }

    companion object {
        fun factory(context: Context): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass.isAssignableFrom(MainViewModel::class.java))
                val owner = AndroidApplicationOwner.get(context)
                return MainViewModel(
                    appContext = context.applicationContext,
                    owner = owner,
                ) as T
            }
        }
    }
}
