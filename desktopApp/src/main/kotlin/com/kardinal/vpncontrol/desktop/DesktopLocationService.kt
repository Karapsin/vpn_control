package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.ImportLocationsDecision
import com.kardinal.vpncontrol.LocationStatusLogic
import com.kardinal.vpncontrol.LocationMutationLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SelectionCandidate
import com.kardinal.vpncontrol.SelectionMappingLogic
import com.kardinal.vpncontrol.SaveLocationDecision
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.control.ControlLocationResolution
import com.kardinal.vpncontrol.control.ControlLocationSelection
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Path

internal class DesktopLocationService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val currentRuntimeMode: () -> AppMode?,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val commitState: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit>,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val isActiveLocation: (DesktopLocationRecord) -> Boolean = { it.rawLink == stateProvider().selectedProfileRawLink },
    private val captureRestore: () -> (suspend () -> Result<Unit>) = {
        { Result.failure(IllegalStateException("ROLLBACK_FAILED")) }
    },
) {
    fun visibleLocations(): List<DesktopLocationRecord> {
        return locationsProvider().filter { it.rawLink in stateProvider().currentLocations }
    }

    fun selectedLocation(): DesktopLocationRecord? {
        val state = stateProvider()
        return locationsProvider().firstOrNull { it.matchesSelectedLocation(state) }
            ?: visibleLocations().firstOrNull { it.isSelected }
    }

    fun saveLocation(raw: String, index: Int? = null, expectedRaw: String? = null): Result<DesktopLocationRecord> {
        val state = stateProvider()
        val locations = locationsProvider()
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        if (state.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) {
            return Result.failure(IllegalArgumentException(LocationStatusMessages.subscriptionLocationSaveReadOnly()))
        }
        val edited = index?.let { id -> locations.firstOrNull { it.index == id } }
        if (index != null && (edited == null || edited.sourceUrl.isNotBlank())) {
            return Result.failure(IllegalArgumentException(LocationStatusMessages.locationEditUnavailable()))
        }
        if (expectedRaw != null && edited?.rawLink != expectedRaw) return Result.failure(IllegalStateException("CONFLICT"))
        val manual = locations.filter { it.sourceUrl.isBlank() }
        val decision = LocationMutationLogic.planSaveLocation(state.copy(
            currentLocations = manual.map { it.rawLink }, locationDraft = raw,
            editingLocationIndex = edited?.let { manual.indexOf(it) },
        ))
        val plan = when (decision) {
            is SaveLocationDecision.Plan -> decision
            is SaveLocationDecision.Invalid -> return Result.failure(IllegalArgumentException(decision.message))
            is SaveLocationDecision.Duplicate -> return Result.failure(IllegalArgumentException(decision.message))
            is SaveLocationDecision.MutationBlocked -> return Result.failure(IllegalArgumentException(decision.message))
        }
        var nextIndex = (locations.maxOfOrNull { it.index } ?: 0) + 1
        val nextManual = plan.nextLocations.distinct().map { link ->
            manual.firstOrNull { it.rawLink == link } ?: listOf(link).toDesktopLocationRecords(
                if (link == plan.normalizedLocation && edited != null) edited.index else nextIndex++,
            ).single()
        }
        val saved = nextManual.first { it.rawLink == plan.normalizedLocation }
        val nextState = if (edited != null && state.selectedProfileRawLink == edited.rawLink) {
            state.copy(selectedProfileRawLink = saved.rawLink, selectedProfileJson = saved.rawLink,
                selectedProfileName = saved.name, selectedProfileServer = saved.server, selectedProfileSourceUrl = "")
        } else state
        return commitState(
            nextState.withStatus(LocationMutationLogic.saveLocationSuccessMessage(plan)),
            locations.filter { it.sourceUrl.isNotBlank() } + nextManual,
        ).map { saved }
    }

    suspend fun deleteLocation(index: Int, expectedLocation: DesktopLocationRecord? = null,
        validateAdmission: () -> Result<Unit> = { Result.success(Unit) },
        guardedCommit: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit> = commitState,
        captureRestoreAction: () -> (suspend () -> Result<Unit>) = captureRestore,
    ): Result<Unit> {
        validateAdmission().getOrElse { return Result.failure(it) }
        val state = stateProvider()
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        val locations = locationsProvider()
        val removed = locations.firstOrNull { it.index == index }
            ?: return Result.failure(IllegalArgumentException("NOT_FOUND"))
        if (expectedLocation != null && (removed.rawLink != expectedLocation.rawLink || removed.sourceUrl != expectedLocation.sourceUrl))
            return Result.failure(IllegalStateException("CONFLICT"))
        if (removed.sourceUrl.isNotBlank()) return Result.failure(IllegalArgumentException("READ_ONLY"))
        val removedSelected = removed.rawLink == state.selectedProfileRawLink
        return commitDesktopRuntimeMutation(
            stopRequired = isActiveLocation(removed) && state.isVpnRunning,
            captureRestore = captureRestoreAction,
            stop = { stopConnection(
                ConnectionStatusMessages.connectionStopped(currentRuntimeMode() ?: state.appMode),
            ) },
            commit = {
                val latestState = stateProvider()
                val updatedLocations = locations.filterNot { it.index == index }
                guardedCommit(
                    latestState.clearSelectedLocationIf(removedSelected)
                        .withStatus(LocationStatusMessages.locationRemoved(removed.name)),
                    updatedLocations,
                )
            },
        )
    }

    fun applySelection(index: Int, messagePrefix: String = "Selected"): Result<Unit> {
        val state = stateProvider()
        val locations = locationsProvider()
        val selected = locations.firstOrNull { it.index == index }
            ?: return Result.failure(IllegalArgumentException("NOT_FOUND"))
        if (selected.rawLink == state.selectedProfileRawLink && selected.sourceUrl == state.selectedProfileSourceUrl &&
            selected.name == state.selectedProfileName && selected.server == state.selectedProfileServer &&
            locations.all { it.isSelected == (it.index == index) }) return Result.success(Unit)
        val updatedLocations = locations.map { it.copy(isSelected = it.index == index) }
        return commitState(
            state.withStatus(ConnectionStatusMessages.selectedLocationSet(selected.name)).copy(
                selectedProfileName = selected.name,
                selectedProfileServer = selected.server,
                selectedProfileRawLink = selected.rawLink,
                selectedProfileSourceUrl = selected.sourceUrl,
            ),
            updatedLocations,
        )
    }

    fun applyCliSelection(target: String): Result<DesktopLocationRecord> {
        val selected = when (val resolution = ControlLocationSelection.resolve(target, visibleLocations(), DesktopLocationRecord::name)) {
            is ControlLocationResolution.Found -> resolution.location
            is ControlLocationResolution.Rejected -> {
                // A failed selector is untrusted input, not a safe log/status label.
                updateState { it.withStatus(ConnectionStatusMessages.selectedLocationSelectFailed()) }
                return Result.failure(IllegalArgumentException(resolution.code.wireName))
            }
        }
        return applySelection(selected.index).map { selected }
    }

    suspend fun importRaw(raw: String,
        validateAdmission: () -> Result<Unit> = { Result.success(Unit) },
        guardedCommit: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit> = commitState,
        captureRestoreAction: () -> (suspend () -> Result<Unit>) = captureRestore,
    ): Result<Unit> {
        validateAdmission().getOrElse { return Result.failure(it) }
        if (stateProvider().isBusy) return Result.failure(IllegalStateException("BUSY"))
        return when (val decision = LocationMutationLogic.planImportLocations(stateProvider(), raw)) {
            is ImportLocationsDecision.Blocked -> {
                updateState { it.withStatus(decision.message) }
                Result.failure(IllegalArgumentException("READ_ONLY"))
            }
            is ImportLocationsDecision.Invalid -> {
                updateState { it.withStatus(decision.message) }
                Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
            }
            is ImportLocationsDecision.Plan -> {
                applyImportPlan(decision, validateAdmission, guardedCommit, captureRestoreAction)
            }
        }
    }

    suspend fun importFromClipboard() {
        val raw = DesktopTextTransfer.readClipboardText()
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: LocationStatusMessages.clipboardReadFailed()) }
            return
        }
        importRaw(raw.getOrThrow())
    }

    suspend fun importFromFile(selection: Result<Path?>) {
        if (selection.isFailure) {
            updateState { it.withStatus(selection.exceptionOrNull()?.message ?: LocationStatusMessages.locationsFileOpenFailed()) }
            return
        }
        val path = selection.getOrNull() ?: return
        val raw = DesktopTextTransfer.readTextFile(path)
        if (raw.isFailure) {
            updateState { it.withStatus(raw.exceptionOrNull()?.message ?: LocationStatusMessages.locationsFileReadFailed()) }
            return
        }
        importRaw(raw.getOrThrow())
    }

    fun exportToClipboard() {
        val state = stateProvider()
        if (state.currentLocations.isEmpty()) {
            updateState { it.withStatus(LocationStatusLogic.noLocationsToExport()) }
            return
        }
        val document = LocationConfigs.export(state.currentLocations)
        val result = DesktopTextTransfer.writeClipboardText(document.content)
        updateState {
            it.withStatus(
                result.exceptionOrNull()?.message ?: LocationStatusMessages.locationsCopiedToClipboard(),
            )
        }
    }

    fun exportToFile(
        window: ComposeWindow,
        title: String = "Export Locations",
    ) {
        val state = stateProvider()
        if (state.currentLocations.isEmpty()) {
            updateState { it.withStatus(LocationStatusLogic.noLocationsToExport()) }
            return
        }
        val document = LocationConfigs.export(state.currentLocations)
        val result = DesktopTextTransfer.saveTextFile(
            window = window,
            title = title,
            suggestedFileName = document.fileName,
            content = document.content,
        )
        updateState {
            it.withStatus(
                result.fold(
                    onSuccess = { path ->
                        if (path == null) {
                            LocationStatusMessages.locationsExportCanceled()
                        } else {
                            LocationStatusMessages.locationsExportedTo(path.toString())
                        }
                    },
                    onFailure = { error -> error.message ?: LocationStatusMessages.locationsExportFailed() },
                ),
            )
        }
    }

    private suspend fun applyImportPlan(decision: ImportLocationsDecision.Plan,
        validateAdmission: () -> Result<Unit>,
        guardedCommit: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit>,
        captureRestoreAction: () -> (suspend () -> Result<Unit>),
    ): Result<Unit> {
        val state = stateProvider()
        val preservedSubscriptionLocations = locationsProvider().filter { it.sourceUrl.isNotBlank() }
        val existingManualReferences = locationsProvider().filter { it.sourceUrl.isBlank() }.associateBy {
            LocationConfigs.normalizeStoredReference(it.rawLink)
        }
        val importedLocations = decision.importedLocations.toDesktopLocationRecords(
            startIndex = nextLocationIndex(preservedSubscriptionLocations),
        ).map { imported ->
            val existing = existingManualReferences[LocationConfigs.normalizeStoredReference(imported.rawLink)]
            // A format-only round trip must retain the reference used by the active runtime.
            if (existing == null) imported else imported.copy(rawLink = existing.rawLink)
        }
        val nextLocations = preservedSubscriptionLocations + importedLocations
        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            nextLocations.none { it.rawLink == state.selectedProfileRawLink }
        val removedActive = locationsProvider().any(isActiveLocation) && nextLocations.none(isActiveLocation)
        validateAdmission().getOrElse { return Result.failure(it) }
        return commitDesktopRuntimeMutation(
            stopRequired = removedActive && state.isVpnRunning,
            captureRestore = captureRestoreAction,
            stop = { stopConnection(
                LocationMutationLogic.importLocationsStoppedStatusMessage(state.appMode),
            ) },
            commit = {
                val latestState = stateProvider()
                val message = if (removedActive && state.isVpnRunning) {
                    LocationMutationLogic.importLocationsStoppedStatusMessage(latestState.appMode)
                } else {
                    LocationMutationLogic.importLocationsStatusMessage(removedSelected)
                }
                guardedCommit(
                    latestState.clearSelectedLocationIf(removedSelected).withStatus(message),
                    nextLocations,
                )
            },
        )
    }
}

internal fun MainUiState.clearSelectedLocationIf(shouldClear: Boolean): MainUiState {
    if (!shouldClear) return this
    return copy(
        selectedProfileName = "",
        selectedProfileServer = "",
        selectedProfileRawLink = "",
        selectedProfileSourceUrl = "",
    )
}

internal fun List<String>.toDesktopLocationRecords(startIndex: Int): List<DesktopLocationRecord> {
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

internal fun DesktopLocationRecord.matchesSelectedLocation(state: MainUiState): Boolean {
    return SelectionMappingLogic.matchesSelectedLocation(
        candidate = SelectionCandidate(
            rawLink = rawLink,
            sourceUrl = sourceUrl,
            name = name,
            server = server,
        ),
        selectedRawLink = state.selectedProfileRawLink,
        selectedSourceUrl = state.selectedProfileSourceUrl,
        selectedName = state.selectedProfileName,
        selectedServer = state.selectedProfileServer,
    )
}
