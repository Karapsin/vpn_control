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
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.RoutingRulesExportDocument
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.data.SubscriptionRefreshScheduler
import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainViewModel(
    private val repository: AppRepository,
    private val vpnManager: VpnManager,
    private val diagnosticsExporter: DiagnosticsExporter,
    private val installedAppsCatalog: InstalledAppsCatalog,
) : ViewModel() {
    private val controller = MainController()
    private val _uiState = controller.mutableState
    val uiState: StateFlow<MainUiState> = controller.state
    private var activeBusyJob: Job? = null
    private val controllerEffectHandler = AndroidControllerEffectHandler(
        repository = repository,
        launch = { block -> viewModelScope.launch { block() } },
        ensureInstalledAppsLoaded = ::ensureInstalledAppsLoaded,
        importRoutingRules = ::importRoutingRules,
    )
    private val profileActions = AndroidProfileActionsService(
        controller = controller,
        stateProvider = { _uiState.value },
        effectSink = controllerEffectHandler,
        launch = { block -> viewModelScope.launch { block() } },
        updateStatus = repository::updateStatus,
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

    init {
        repository.state.onEach { persisted ->
            controller.mergePersistedState(persisted)
        }.launchIn(viewModelScope)

        viewModelScope.launch {
            repository.syncSubscriptionRefreshScheduling()
        }
    }

    fun toggleDnsDialog() {
        controller.toggleDnsDialog()
    }

    fun toggleUiSettingsDialog() {
        controller.toggleUiSettingsDialog()
    }

    fun setSessionStatsEnabled(enabled: Boolean) {
        controller.setSessionStatsEnabled(enabled)
        viewModelScope.launch {
            repository.updateSessionStatsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Session stats enabled" else "Session stats hidden",
            )
        }
    }

    fun setLiveTrafficStatsEnabled(enabled: Boolean) {
        controller.setLiveTrafficStatsEnabled(enabled)
        viewModelScope.launch {
            repository.updateLiveTrafficStatsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Live traffic stats enabled" else "Live traffic stats hidden",
            )
        }
    }

    fun setProfileTotalsEnabled(enabled: Boolean) {
        controller.setProfileTotalsEnabled(enabled)
        viewModelScope.launch {
            repository.updateProfileTotalsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Per-profile totals enabled" else "Per-profile totals hidden",
            )
        }
    }

    fun setLatencyHistoryEnabled(enabled: Boolean) {
        controller.setLatencyHistoryEnabled(enabled)
        viewModelScope.launch {
            repository.updateLatencyHistoryEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Latency history enabled" else "Latency history hidden",
            )
        }
    }

    fun setConnectionLogEnabled(enabled: Boolean) {
        controller.setConnectionLogEnabled(enabled)
        viewModelScope.launch {
            repository.updateConnectionLogEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Connection log enabled" else "Connection log hidden",
            )
        }
    }

    fun setConnectionTestToolsEnabled(enabled: Boolean) {
        controller.setConnectionTestToolsEnabled(enabled)
        viewModelScope.launch {
            repository.updateConnectionTestToolsEnabled(enabled)
            repository.updateStatus(
                if (enabled) "Connection test tools enabled" else "Connection test tools hidden",
            )
        }
    }

    fun toggleAppModeDialog() {
        controller.toggleAppModeDialog()
    }

    fun toggleRefreshPolicyDialog() {
        controller.toggleRefreshPolicyDialog()
    }

    fun toggleValidationSettingsDialog() {
        controller.toggleValidationSettingsDialog()
    }

    fun toggleLanguageDialog() {
        controller.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        handleControllerEffects(controller.setAppLanguage(language))
    }

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

    fun setProfileSourceMode(value: ProfileSourceMode) {
        profileActions.setProfileSourceMode(value)
    }

    fun setAppMode(value: AppMode) {
        handleControllerEffects(controller.setAppMode(value))
    }

    fun onDnsDraftChanged(value: String) {
        controller.onDnsDraftChanged(value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        controller.onCustomDnsEnabledChanged(enabled)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        controller.onSubscriptionRefreshPolicyDraftChanged(policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        controller.onFindBestAfterSubscriptionRefreshDraftChanged(enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        controller.onSubscriptionRefreshCustomHoursDraftChanged(value)
    }

    fun onValidationPrimaryUrlDraftChanged(value: String) {
        controller.onValidationPrimaryUrlDraftChanged(value)
    }

    fun onValidationSecondaryUrlDraftChanged(value: String) {
        controller.onValidationSecondaryUrlDraftChanged(value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        controller.onValidationBatchSizeDraftChanged(value)
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        controller.onValidationRetryCountDraftChanged(value)
    }

    fun onRoutingIgnoreRulesDraftChanged(enabled: Boolean) {
        controller.onRoutingIgnoreRulesDraftChanged(enabled)
    }

    fun onRoutingAppSearchChanged(value: String) {
        controller.onRoutingAppSearchChanged(value)
    }

    fun onRoutingNationalDomainsDraftChanged(value: String) {
        controller.onRoutingNationalDomainsDraftChanged(value)
    }

    fun onRoutingDirectDomainsDraftChanged(value: String) {
        controller.onRoutingDirectDomainsDraftChanged(value)
    }

    fun showAddRuleSetDialog() {
        controller.showAddRuleSetDialog()
    }

    fun editRuleSet(id: String) {
        controller.editRuleSet(id)
    }

    fun closeRuleSetDialog() {
        controller.closeRuleSetDialog()
    }

    fun onRuleSetNameDraftChanged(value: String) {
        controller.onRuleSetNameDraftChanged(value)
    }

    fun onRuleSetSourceDraftChanged(value: String) {
        controller.onRuleSetSourceDraftChanged(value)
    }

    fun onRuleSetSourceTypeDraftChanged(value: RoutingRuleSetSourceType) {
        controller.onRuleSetSourceTypeDraftChanged(value)
    }

    fun onRuleSetFormatDraftChanged(value: RoutingRuleSetFormat) {
        controller.onRuleSetFormatDraftChanged(value)
    }

    fun onRuleSetActionDraftChanged(value: RoutingRuleSetAction) {
        controller.onRuleSetActionDraftChanged(value)
    }

    fun onRuleSetUpdateHoursDraftChanged(value: String) {
        controller.onRuleSetUpdateHoursDraftChanged(value)
    }

    fun saveRuleSet() {
        handleControllerEffects(controller.saveRuleSet())
    }

    fun deleteRuleSet(id: String) {
        handleControllerEffects(controller.deleteRuleSet(id))
    }

    fun showAddLocationDialog() {
        handleControllerEffects(controller.showAddLocationDialog())
    }

    fun editLocation(index: Int) {
        val rawLink = _uiState.value.currentLocations.getOrNull(index) ?: return
        controller.editLocation(
            index = index,
            rawLink = runCatching { LocationConfigs.prettyStoredLocation(rawLink) }.getOrDefault(rawLink),
        )
    }

    fun closeLocationDialog() {
        controller.closeLocationDialog()
    }

    fun closeLocationMutationBlockedDialog() {
        controller.closeLocationMutationBlockedDialog()
    }

    private fun showLocationMutationBlockedDialog(message: String) {
        controller.showLocationMutationBlockedDialog(message)
    }

    fun onLocationDraftChanged(value: String) {
        controller.onLocationDraftChanged(value)
    }

    fun toggleProxyRoutingApp(packageName: String) {
        controller.toggleProxyRoutingApp(packageName)
    }

    fun toggleDirectRoutingApp(packageName: String) {
        controller.toggleDirectRoutingApp(packageName)
    }

    fun selectAllVisibleProxyApps() {
        controller.selectAllVisibleProxyApps(filteredRoutingPackages())
    }

    fun clearAllVisibleProxyApps() {
        controller.clearAllVisibleProxyApps(filteredRoutingPackages())
    }

    fun selectAllVisibleDirectApps() {
        controller.selectAllVisibleDirectApps(filteredRoutingPackages())
    }

    fun clearAllVisibleDirectApps() {
        controller.clearAllVisibleDirectApps(filteredRoutingPackages())
    }

    fun onVpnPermissionGranted() {
        controller.onVpnPermissionGranted()
    }

    fun saveProfile() {
        profileActions.saveProfile()
    }

    fun clearProfileSource() {
        profileActions.clearProfileSource()
    }

    fun refreshActiveSubscriptionCache() {
        viewModelScope.launch {
            if (_uiState.value.subscriptions.isEmpty()) {
                repository.updateStatus(SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE)
                return@launch
            }
            setBusy(true)
            try {
                val refreshAll = _uiState.value.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID
                repository.updateStatus(
                    SubscriptionRefreshResultLogic.refreshStartMessage(
                        targetCount = if (refreshAll) _uiState.value.subscriptions.size else 1,
                    ),
                )
                val result = repository.refreshActiveSubscriptionCache()
                repository.updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            SubscriptionRefreshResultLogic.manualSummary(
                                scope = if (refreshAll) {
                                    SubscriptionRefreshScope.ALL
                                } else {
                                    SubscriptionRefreshScope.ACTIVE
                                },
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptionNames = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = if (refreshAll) _uiState.value.subscriptions.size else 1,
                            )
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
                repository.updateStatus(SubscriptionRefreshResultLogic.NO_SUBSCRIPTIONS_MESSAGE)
                return@launch
            }
            setBusy(true)
            try {
                repository.updateStatus(
                    SubscriptionRefreshResultLogic.refreshStartMessage(
                        targetCount = _uiState.value.subscriptions.size,
                    ),
                )
                val result = repository.refreshAllSubscriptionsCaches()
                repository.updateStatus(
                    result.fold(
                        onSuccess = { refresh ->
                            SubscriptionRefreshResultLogic.manualSummary(
                                scope = SubscriptionRefreshScope.ALL,
                                refreshedCount = refresh.refreshedCount,
                                failedSubscriptionNames = refresh.failedSubscriptions.map { it.displayName },
                                totalCount = _uiState.value.subscriptions.size,
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
        handleControllerEffects(controller.saveSubscriptionRefreshPolicy())
    }

    fun saveValidationSettings() {
        handleControllerEffects(controller.saveValidationSettings())
    }

    fun saveLocation() {
        val decision = LocationMutationLogic.planSaveLocation(_uiState.value)
        viewModelScope.launch {
            when (decision) {
                is SaveLocationDecision.MutationBlocked -> {
                    showLocationMutationBlockedDialog(decision.message)
                    return@launch
                }
                is SaveLocationDecision.Invalid -> {
                    repository.updateStatus(decision.message)
                    return@launch
                }
                is SaveLocationDecision.Duplicate -> {
                    repository.updateStatus(decision.message)
                    return@launch
                }
                is SaveLocationDecision.Plan -> Unit
            }
            val plan = decision as SaveLocationDecision.Plan
            val previousState = repository.snapshot()
            repository.updateCurrentLocations(plan.nextLocations)
            if (plan.replacedRawLink != null && plan.replacedRawLink == selectedLocationReference()) {
                val selectionResult = repository.selectionFromRawLink(
                    rawLink = plan.normalizedLocation,
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
                val applyResult = connectionLifecycle.applyAndPersistSelection(
                    selection = selectionResult.getOrThrow(),
                    statusMessage = "Applying updated selected location...",
                )
                if (!applyResult.isSuccess) {
                    val message = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                        result = applyResult,
                        texts = SelectionCommitFailureTexts(
                            applyFailureFallback = "Failed to apply updated selected location",
                            persistFailureWithoutApplyFallback = "Failed to save the updated selected location",
                            persistFailureAfterApplyFallback = "Updated selected location applied, but failed to save it",
                        ),
                    )
                    val resolvedMessage = if (applyResult.requiresLiveRollback) {
                        connectionLifecycle.rollbackSelectionChange(previousState, message)
                    } else {
                        repository.restoreSnapshot(previousState)
                        message
                    }
                    repository.updateStatus(resolvedMessage)
                    return@launch
                }
            }
            repository.updateStatus(LocationMutationLogic.saveLocationSuccessMessage(plan))
            closeLocationDialog()
        }
    }

    fun deleteLocation(index: Int) {
        when (val decision = LocationMutationLogic.planDeleteLocation(_uiState.value, index)) {
            is DeleteLocationDecision.MutationBlocked -> {
                showLocationMutationBlockedDialog(decision.message)
                return
            }
            DeleteLocationDecision.Missing -> return
            is DeleteLocationDecision.Plan -> viewModelScope.launch {
                val previousState = repository.snapshot()
                val update = repository.updateCurrentLocations(decision.nextLocations)
                val removedSelected = update.selectedMissing
                if (removedSelected && _uiState.value.isVpnRunning) {
                    val stopResult = vpnManager.stop()
                    repository.updateStatus(
                        stopResult.fold(
                            onSuccess = {
                                LocationMutationLogic.deleteLocationStoppedStatusMessage(
                                    appMode = _uiState.value.appMode,
                                    remarks = decision.remarks,
                                )
                            },
                            onFailure = {
                                repository.restoreSnapshot(previousState)
                                it.message ?: LocationMutationLogic.deleteLocationRollbackFailureMessage(
                                    _uiState.value.appMode,
                                )
                            },
                        ),
                    )
                } else {
                    repository.updateStatus(
                        LocationMutationLogic.deleteLocationStatusMessage(
                            removedSelected = removedSelected,
                            appMode = _uiState.value.appMode,
                            remarks = decision.remarks,
                        ),
                    )
                }
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
                    val applyResult = connectionLifecycle.applyAndPersistSelection(
                        selection = selectionResult.getOrThrow(),
                        statusMessage = "Applying selected location...",
                    )
                    if (!applyResult.isSuccess) {
                        val message = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                            result = applyResult,
                            texts = SelectionCommitFailureTexts(
                                applyFailureFallback = "Failed to apply selected location",
                                persistFailureWithoutApplyFallback = "Failed to save selected location",
                                persistFailureAfterApplyFallback = "Selected location applied, but failed to save it",
                            ),
                        )
                        val resolvedMessage = if (applyResult.requiresLiveRollback) {
                            connectionLifecycle.rollbackSelectionChange(previousState, message)
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
        handleControllerEffects(controller.saveDns())
    }

    fun saveRoutingRules() {
        val rules = MainDraftLogic.buildEditedRoutingRules(_uiState.value)
        viewModelScope.launch {
            setBusy(true)
            val result = repository.updateRoutingRules(rules)
            repository.updateStatus(
                result.fold(
                    onSuccess = {
                        if (_uiState.value.isVpnRunning) {
                            "Routing rules saved. Restart ${MainCommandLogic.connectionNoun(_uiState.value.appMode)} to apply"
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
        return RoutingRulesTransfer.export(MainDraftLogic.buildEditedRoutingRules(_uiState.value))
    }

    fun buildLocationsExport(): LocationsExportDocument {
        return LocationConfigs.export(_uiState.value.currentLocations)
    }

    fun importLocations(raw: String) {
        viewModelScope.launch {
            when (val decision = LocationMutationLogic.planImportLocations(_uiState.value, raw)) {
                is ImportLocationsDecision.Blocked -> {
                    repository.updateStatus(decision.message)
                    return@launch
                }
                is ImportLocationsDecision.Invalid -> {
                    repository.updateStatus(decision.message)
                    return@launch
                }
                is ImportLocationsDecision.Plan -> {
                    setBusy(true)
                    val previousState = repository.snapshot()
                    val update = repository.updateCurrentLocations(decision.importedLocations)
                    val removedSelected = update.selectedMissing &&
                        _uiState.value.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS
                    if (removedSelected && _uiState.value.isVpnRunning) {
                        val stopResult = vpnManager.stop()
                        repository.updateStatus(
                            stopResult.fold(
                                onSuccess = {
                                    LocationMutationLogic.importLocationsStoppedStatusMessage(
                                        _uiState.value.appMode,
                                    )
                                },
                                onFailure = {
                                    repository.restoreSnapshot(previousState)
                                    it.message ?: LocationMutationLogic.importLocationsRollbackFailureMessage(
                                        _uiState.value.appMode,
                                    )
                                },
                            ),
                        )
                    } else {
                        repository.updateStatus(
                            LocationMutationLogic.importLocationsStatusMessage(removedSelected),
                        )
                    }
                    setBusy(false)
                }
            }
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

            val rules = MainDraftLogic.sanitizeRoutingRules(parsed.getOrThrow())
            val result = repository.updateRoutingRules(rules)
            repository.updateStatus(
                result.fold(
                    onSuccess = {
                        controller.applyImportedRoutingRules(rules)
                        if (_uiState.value.isVpnRunning) {
                            "Routing rules imported. Restart ${MainCommandLogic.connectionNoun(_uiState.value.appMode)} to apply"
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
            val preconditionError = MainCommandLogic.refreshPreconditionError(_uiState.value)
            if (preconditionError != null) {
                repository.updateStatus(preconditionError)
                return@launchTrackedBusyOperation
            }
            setBusy(true)
            _uiState.value = _uiState.value.copy(isRefreshing = true)
            val previousState = repository.snapshot()
            var startAttempted = false
            try {
                repository.updateStatus(MainCommandLogic.refreshStartMessage(_uiState.value))
                val result = findBestProfileWithRetries()
                val message = result.fold(
                    onSuccess = { selection ->
                        startAttempted = true
                        val applyResult = connectionLifecycle.startAndPersistSelection(
                            selection = selection,
                            statusMessage = MainCommandLogic.bestSelectionStartMessage(_uiState.value.appMode),
                        )
                        if (applyResult.isSuccess) {
                            appendLatencyHistory(selection.benchmark)
                            ConnectionOrchestrationLogic.refreshSelectionStartedMessage(
                                appMode = _uiState.value.appMode,
                                remarks = selection.profile.remarks,
                            )
                        } else if (applyResult.requiresLiveRollback) {
                            connectionLifecycle.rollbackSelectionChange(
                                previousState = previousState,
                                baseMessage = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                                    result = applyResult,
                                    texts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(
                                        _uiState.value.appMode,
                                    ),
                                ),
                            )
                        } else {
                            if (applyResult.shouldRestoreSnapshot) {
                                repository.restoreSnapshot(previousState)
                            }
                            ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                                result = applyResult,
                                texts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(
                                    _uiState.value.appMode,
                                ),
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
                            connectionLifecycle.rollbackSelectionChange(previousState, "Location search cancelled.")
                        startAttempted -> {
                            val stopResult = vpnManager.stop()
                            stopResult.fold(
                                onSuccess = {
                                    repository.restoreSnapshot(previousState)
                                    ConnectionOrchestrationLogic.refreshCancelledMessage()
                                },
                                onFailure = {
                                    ConnectionOrchestrationLogic.cancelledWithStopFailureMessage(
                                        prefix = "Location search cancelled.",
                                        appMode = _uiState.value.appMode,
                                        errorMessage = it.message,
                                    )
                                },
                            )
                        }
                        else -> ConnectionOrchestrationLogic.refreshCancelledMessage()
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
            connectionLifecycle.toggleConnection()
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

    private fun handleControllerEffects(effects: List<MainControllerEffect>) {
        controllerEffectHandler.handle(effects)
    }

    private fun setBusy(value: Boolean) {
        _uiState.value = _uiState.value.copy(isBusy = value)
    }

    private suspend fun findBestProfileWithRetries(): Result<com.kardinal.vpncontrol.model.ProfileSelection> {
        return ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = _uiState.value.validationSettings.retryCount,
            onRetryStatus = { message -> repository.updateStatus(message) },
            action = { repository.refreshBestProfile() },
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
