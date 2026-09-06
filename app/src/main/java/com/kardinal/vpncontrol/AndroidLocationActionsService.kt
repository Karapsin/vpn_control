package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.LocationsExportDocument
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.shared.storageapi.LocationUpdateResult
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal class AndroidLocationActionsService(
    private val controller: MainController,
    private val stateProvider: () -> MainUiState,
    private val launch: (suspend () -> Unit) -> Unit,
    private val launchTrackedBusyOperation: (suspend () -> Unit) -> Unit,
    private val setBusy: (Boolean) -> Unit,
    private val setRefreshing: (Boolean) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val snapshot: suspend () -> PersistedState,
    private val restoreSnapshot: suspend (PersistedState) -> Unit,
    private val updateCurrentLocations: suspend (List<String>) -> LocationUpdateResult,
    private val selectionFromRawLink: suspend (rawLink: String, detail: String) -> Result<ProfileSelection>,
    private val applyAndPersistSelection: suspend (selection: ProfileSelection, statusMessage: String) -> SelectionCommitResult,
    private val rollbackSelectionChange: suspend (previousState: PersistedState, baseMessage: String) -> String,
    private val stopConnection: suspend () -> Result<Unit>,
    private val benchmarkLocation: suspend (String) -> Result<ProfileBenchmark>,
    private val appendLatencyHistory: suspend (LatencyHistoryEntry) -> Unit,
    private val launchMutation: (suspend () -> Unit) -> Unit = launchTrackedBusyOperation,
    private val guarded: AndroidGuiLocationActions? = null,
) {
    fun editLocation(target: AndroidRenderedLocationTarget) { guarded?.openTarget(target) }
    fun selectLocation(target: AndroidRenderedLocationTarget) { guarded?.select(target) }
    fun deleteLocation(target: AndroidRenderedLocationTarget) { guarded?.delete(target) }
    fun showAddLocationDialog() {
        guarded?.let { it.open(); return }
        effectStatus(controller.showAddLocationDialog())
    }

    fun editLocation(index: Int) {
        val rawLink = stateProvider().currentLocations.getOrNull(index) ?: return
        guarded?.let { it.open(rawLink); return }
        controller.editLocation(
            index = index,
            rawLink = runCatching { LocationConfigs.prettyStoredLocation(rawLink) }.getOrDefault(rawLink),
        )
    }

    fun closeLocationDialog() {
        guarded?.close()
        controller.closeLocationDialog()
    }

    fun closeLocationMutationBlockedDialog() {
        controller.closeLocationMutationBlockedDialog()
    }

    fun onLocationDraftChanged(value: String) {
        controller.onLocationDraftChanged(value)
    }

    fun saveLocation() {
        guarded?.let { it.save(); return }
        val decision = LocationMutationLogic.planSaveLocation(stateProvider())
        launchMutation mutation@{
            when (decision) {
                is SaveLocationDecision.MutationBlocked -> {
                    controller.showLocationMutationBlockedDialog(decision.message)
                    return@mutation
                }
                is SaveLocationDecision.Invalid -> {
                    updateStatus(decision.message)
                    return@mutation
                }
                is SaveLocationDecision.Duplicate -> {
                    updateStatus(decision.message)
                    return@mutation
                }
                is SaveLocationDecision.Plan -> Unit
            }
            val plan = decision as SaveLocationDecision.Plan
            val previousState = snapshot()
            updateCurrentLocations(plan.nextLocations)
            if (plan.replacedRawLink != null && plan.replacedRawLink == selectedLocationReference()) {
                val selectionResult = selectionFromRawLink(
                    plan.normalizedLocation,
                    "Selected location updated",
                )
                if (selectionResult.isFailure) {
                    restoreSnapshot(previousState)
                    updateStatus(
                        selectionResult.exceptionOrNull()?.message
                            ?: ConnectionStatusMessages.updatedSelectedLocationApplyFailed(),
                    )
                    return@mutation
                }
                val applyResult = applyAndPersistSelection(
                    selectionResult.getOrThrow(),
                    ConnectionStatusMessages.updatedSelectedLocationApplying(),
                )
                if (!applyResult.isSuccess) {
                    val message = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                        result = applyResult,
                        texts = SelectionCommitFailureTexts(
                            applyFailureFallback = ConnectionStatusMessages.updatedSelectedLocationApplyFailed(),
                            persistFailureWithoutApplyFallback = ConnectionStatusMessages.updatedSelectedLocationSaveFailed(),
                            persistFailureAfterApplyFallback = ConnectionStatusMessages.updatedSelectedLocationAppliedSaveFailed(),
                        ),
                    )
                    val resolvedMessage = if (applyResult.requiresLiveRollback) {
                        rollbackSelectionChange(previousState, message)
                    } else {
                        restoreSnapshot(previousState)
                        message
                    }
                    updateStatus(resolvedMessage)
                    return@mutation
                }
            }
            updateStatus(LocationMutationLogic.saveLocationSuccessMessage(plan))
            closeLocationDialog()
        }
    }

    fun deleteLocation(index: Int) {
        guarded?.let { actions -> stateProvider().currentLocations.getOrNull(index)?.let(actions::delete); return }
        when (val decision = LocationMutationLogic.planDeleteLocation(stateProvider(), index)) {
            is DeleteLocationDecision.MutationBlocked -> {
                controller.showLocationMutationBlockedDialog(decision.message)
                return
            }
            DeleteLocationDecision.Missing -> return
            is DeleteLocationDecision.Plan -> launchMutation {
                val previousState = snapshot()
                val update = updateCurrentLocations(decision.nextLocations)
                val removedSelected = update.selectedMissing
                if (removedSelected && stateProvider().isVpnRunning) {
                    val stopResult = stopConnection()
                    updateStatus(
                        stopResult.fold(
                            onSuccess = {
                                LocationMutationLogic.deleteLocationStoppedStatusMessage(
                                    appMode = stateProvider().appMode,
                                    remarks = decision.remarks,
                                )
                            },
                            onFailure = {
                                restoreSnapshot(previousState)
                                it.message ?: LocationMutationLogic.deleteLocationRollbackFailureMessage(
                                    stateProvider().appMode,
                                )
                            },
                        ),
                    )
                } else {
                    updateStatus(
                        LocationMutationLogic.deleteLocationStatusMessage(
                            removedSelected = removedSelected,
                            appMode = stateProvider().appMode,
                            remarks = decision.remarks,
                        ),
                    )
                }
            }
        }
    }

    fun deleteLocation(raw: String) {
        guarded?.let { it.delete(raw); return }
        val index = stateProvider().currentLocations.indexOf(raw)
        if (index >= 0) deleteLocation(index)
    }

    fun benchmarkLocation(index: Int) {
        val rawLink = stateProvider().currentLocations.getOrNull(index) ?: return
        benchmarkLocationStored(rawLink)
    }

    fun benchmarkSelectedLocationFromStats() {
        val rawLink = selectedLocationReference().ifBlank {
            stateProvider().currentLocations.firstOrNull {
                it == selectedLocationReference()
            }.orEmpty()
        }
        if (rawLink.isBlank()) {
            launch {
                updateStatus(LocationStatusLogic.selectLocationFirst())
            }
            return
        }
        benchmarkLocationStored(rawLink)
    }

    fun selectLocation(index: Int) {
        val rawLink = stateProvider().currentLocations.getOrNull(index) ?: return
        guarded?.let { it.select(rawLink); return }
        launchMutation {
            setBusy(true)
            val isSelected = rawLink == selectedLocationReference()
            val previousState = snapshot()
            val result = if (isSelected) {
                Result.success(Unit)
            } else {
                val selectionResult = selectionFromRawLink(rawLink, "Selected location manually")
                if (selectionResult.isFailure) {
                    Result.failure(
                        selectionResult.exceptionOrNull()
                            ?: IllegalStateException(ConnectionStatusMessages.selectedLocationSelectFailed()),
                    )
                } else {
                    val applyResult = applyAndPersistSelection(
                        selectionResult.getOrThrow(),
                        ConnectionStatusMessages.selectedLocationApplying(),
                    )
                    if (!applyResult.isSuccess) {
                        val message = ConnectionOrchestrationLogic.selectionCommitFailureMessage(
                            result = applyResult,
                            texts = SelectionCommitFailureTexts(
                                applyFailureFallback = ConnectionStatusMessages.selectedLocationApplyFailed(),
                                persistFailureWithoutApplyFallback = ConnectionStatusMessages.selectedLocationSaveFailed(),
                                persistFailureAfterApplyFallback = ConnectionStatusMessages.selectedLocationStartedSaveFailed(
                                    stateProvider().appMode,
                                ),
                            ),
                        )
                        val resolvedMessage = if (applyResult.requiresLiveRollback) {
                            rollbackSelectionChange(previousState, message)
                        } else {
                            if (applyResult.shouldRestoreSnapshot) {
                                restoreSnapshot(previousState)
                            }
                            message
                        }
                        Result.failure(IllegalStateException(resolvedMessage))
                    } else {
                        Result.success(Unit)
                    }
                }
            }
            updateStatus(
                if (result.isSuccess) {
                    val remarks = runCatching { LocationConfigs.decodeStoredLocation(rawLink).remarks }
                        .getOrDefault("Location")
                    if (isSelected) {
                        ConnectionStatusMessages.selectedLocationUnchanged(remarks)
                    } else {
                        ConnectionStatusMessages.selectedLocationSet(remarks)
                    }
                } else {
                    result.exceptionOrNull()?.message ?: ConnectionStatusMessages.selectedLocationSelectFailed()
                },
            )
            setBusy(false)
        }
    }

    fun buildLocationsExport(): LocationsExportDocument {
        return LocationConfigs.export(stateProvider().currentLocations)
    }

    fun beginImportLocations(openPicker: () -> Unit) { guarded?.beginImport(openPicker) ?: openPicker() }
    fun cancelImportLocations() { guarded?.cancelImport() }

    fun importLocations(raw: String) {
        guarded?.let { it.import(raw); return }
        launchMutation mutation@{
            when (val decision = LocationMutationLogic.planImportLocations(stateProvider(), raw)) {
                is ImportLocationsDecision.Blocked -> {
                    updateStatus(decision.message)
                    return@mutation
                }
                is ImportLocationsDecision.Invalid -> {
                    updateStatus(decision.message)
                    return@mutation
                }
                is ImportLocationsDecision.Plan -> {
                    setBusy(true)
                    val previousState = snapshot()
                    val update = updateCurrentLocations(decision.importedLocations)
                    val removedSelected = update.selectedMissing &&
                        stateProvider().profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS
                    if (removedSelected && stateProvider().isVpnRunning) {
                        val stopResult = stopConnection()
                        updateStatus(
                            stopResult.fold(
                                onSuccess = {
                                    LocationMutationLogic.importLocationsStoppedStatusMessage(
                                        stateProvider().appMode,
                                    )
                                },
                                onFailure = {
                                    restoreSnapshot(previousState)
                                    it.message ?: LocationMutationLogic.importLocationsRollbackFailureMessage(
                                        stateProvider().appMode,
                                    )
                                },
                            ),
                        )
                    } else {
                        updateStatus(
                            LocationMutationLogic.importLocationsStatusMessage(removedSelected),
                        )
                    }
                    setBusy(false)
                }
            }
        }
    }

    private fun effectStatus(effects: List<MainControllerEffect>) {
        effects.forEach { effect ->
            if (effect is MainControllerEffect.UpdateStatus) {
                launch { updateStatus(effect.message) }
            }
        }
    }

    private fun selectedLocationReference(): String {
        val state = stateProvider()
        return LocationConfigs.selectedStoredReference(
            selectedProfileJson = state.selectedProfileJson,
            selectedProfileRawLink = state.selectedProfileRawLink,
        )
    }

    private fun benchmarkLocationStored(rawLink: String) {
        launchTrackedBusyOperation {
            setBusy(true)
            setRefreshing(true)
            try {
                val remarks = runCatching { LocationConfigs.decodeStoredLocation(rawLink).remarks }
                    .getOrDefault("Location")
                updateStatus(LocationStatusLogic.checkingLocation(remarks))
                val result = benchmarkLocation(rawLink)
                result.onSuccess { benchmark ->
                    appendLatencyHistory(benchmark.toLatencyHistoryEntry())
                }
                updateStatus(
                    result.fold(
                        onSuccess = { benchmark -> LocationStatusMessages.locationChecked(benchmark.profile.remarks) },
                        onFailure = { it.message ?: LocationStatusMessages.locationCheckFailed() },
                    ),
                )
            } catch (_: CancellationException) {
                withContext(NonCancellable) {
                    updateStatus(LocationStatusLogic.locationCheckCancelled())
                }
            } finally {
                setRefreshing(false)
                setBusy(false)
            }
        }
    }

    private fun ProfileBenchmark.toLatencyHistoryEntry(): LatencyHistoryEntry {
        return LatencyHistoryEntry(
            id = UUID.randomUUID().toString(),
            profileName = profile.remarks,
            detail = detail,
            primaryStatus = primaryStatus,
            secondaryStatus = secondaryStatus,
            primaryTotalMs = primaryTotal,
            secondaryTotalMs = secondaryTotal,
            createdAtEpochMillis = System.currentTimeMillis(),
        )
    }
}
