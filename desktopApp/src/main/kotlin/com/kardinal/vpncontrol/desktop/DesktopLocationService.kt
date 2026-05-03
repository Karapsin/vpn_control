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
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import java.nio.file.Path

internal class DesktopLocationService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val currentRuntimeMode: () -> AppMode?,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val commitState: (MainUiState, List<DesktopLocationRecord>) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    fun visibleLocations(): List<DesktopLocationRecord> {
        return locationsProvider().filter { it.rawLink in stateProvider().currentLocations }
    }

    fun selectedLocation(): DesktopLocationRecord? {
        val state = stateProvider()
        return locationsProvider().firstOrNull { it.matchesSelectedLocation(state) }
            ?: visibleLocations().firstOrNull { it.isSelected }
    }

    fun addSampleLocation() {
        val locations = locationsProvider()
        val nextIndex = (locations.maxOfOrNull { it.index } ?: 0) + 1
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
            stateProvider().withStatus(LocationStatusMessages.locationAdded(newLocation.name)),
            locations + newLocation,
        )
    }

    fun editLocation(index: Int) {
        val updatedLocations = locationsProvider().map { location ->
            if (location.index == index) {
                location.copy(name = "${location.name} (edited)")
            } else {
                location
            }
        }
        commitState(
            stateProvider().withStatus(LocationStatusMessages.locationEdited(index)),
            updatedLocations,
        )
    }

    suspend fun deleteLocation(index: Int) {
        val state = stateProvider()
        val locations = locationsProvider()
        val removed = locations.firstOrNull { it.index == index } ?: return
        val removedSelected = removed.rawLink == state.selectedProfileRawLink
        if (removedSelected && state.isVpnRunning) {
            val stopResult = stopConnection(
                ConnectionStatusMessages.connectionStopped(currentRuntimeMode() ?: state.appMode),
            )
            if (stopResult.isFailure) {
                return
            }
        }
        val latestState = stateProvider()
        val updatedLocations = locations.filterNot { it.index == index }
        commitState(
            latestState.clearSelectedLocationIf(removedSelected)
                .withStatus(LocationStatusMessages.locationRemoved(removed.name)),
            updatedLocations,
        )
    }

    fun applySelection(index: Int, messagePrefix: String = "Selected") {
        val state = stateProvider()
        val locations = locationsProvider()
        val selected = locations.firstOrNull { it.index == index } ?: return
        val updatedLocations = locations.map { it.copy(isSelected = it.index == index) }
        commitState(
            state.withStatus(ConnectionStatusMessages.selectedLocationSet(selected.name)).copy(
                selectedProfileName = selected.name,
                selectedProfileServer = selected.server,
                selectedProfileRawLink = selected.rawLink,
                selectedProfileSourceUrl = selected.sourceUrl,
            ),
            updatedLocations,
        )
    }

    suspend fun importRaw(raw: String) {
        when (val decision = LocationMutationLogic.planImportLocations(stateProvider(), raw)) {
            is ImportLocationsDecision.Blocked -> {
                updateState { it.withStatus(decision.message) }
            }
            is ImportLocationsDecision.Invalid -> {
                updateState { it.withStatus(decision.message) }
            }
            is ImportLocationsDecision.Plan -> {
                applyImportPlan(decision)
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

    private suspend fun applyImportPlan(decision: ImportLocationsDecision.Plan) {
        val state = stateProvider()
        val preservedSubscriptionLocations = locationsProvider().filter { it.sourceUrl.isNotBlank() }
        val importedLocations = decision.importedLocations.toDesktopLocationRecords(
            startIndex = nextLocationIndex(preservedSubscriptionLocations),
        )
        val nextLocations = preservedSubscriptionLocations + importedLocations
        val removedSelected = state.selectedProfileRawLink.isNotBlank() &&
            nextLocations.none { it.rawLink == state.selectedProfileRawLink }
        if (removedSelected && state.isVpnRunning) {
            val stopResult = stopConnection(
                LocationMutationLogic.importLocationsStoppedStatusMessage(state.appMode),
            )
            if (stopResult.isFailure) {
                return
            }
        }
        val latestState = stateProvider()
        val message = if (removedSelected && latestState.isVpnRunning) {
            LocationMutationLogic.importLocationsStoppedStatusMessage(latestState.appMode)
        } else {
            LocationMutationLogic.importLocationsStatusMessage(removedSelected)
        }
        commitState(
            latestState.clearSelectedLocationIf(removedSelected)
                .copy(isVpnRunning = if (removedSelected) false else latestState.isVpnRunning)
                .withStatus(message),
            nextLocations,
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
