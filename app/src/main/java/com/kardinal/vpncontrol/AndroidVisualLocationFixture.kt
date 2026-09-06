package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.ProfileSourceMode

/** Synthetic presentation only; never observes or changes an application owner/runtime. */
internal class AndroidVisualCaptureFrame(val state: MainUiState, val locations: AndroidLocationVisualState)

internal fun androidVisualCaptureFrame(state: MainUiState): AndroidVisualCaptureFrame {
    val reference = state.selectedProfileRawLink.ifBlank { state.selectedProfileJson }
    return AndroidVisualCaptureFrame(state, AndroidLocationVisualState(
        activeLocationKey = reference.takeIf { state.isVpnRunning && it.isNotBlank() }?.let {
            androidLocationVisualKey(it, if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) "" else state.selectedProfileSourceUrl)
        },
        restartRequired = state.homeSshRestartPending && state.isVpnRunning,
    ))
}

/** Match production's stored-reference shape for the existing selected-row scene. */
internal fun androidSelectedLocationVisualFixture(state: MainUiState): MainUiState {
    val selected = LocationConfigs.normalizeStoredReference(state.selectedProfileRawLink)
    val profile = LocationConfigs.decodeStoredLocation(selected)
    return state.copy(isVpnRunning = true,
        currentLocations = state.currentLocations.map(LocationConfigs::normalizeStoredReference),
        selectedProfileJson = selected, selectedProfileRawLink = profile.rawLink,
        selectedProfileName = profile.remarks,
        locationBenchmarkDetails = state.locationBenchmarkDetails.mapKeys { LocationConfigs.normalizeStoredReference(it.key) },
    )
}
