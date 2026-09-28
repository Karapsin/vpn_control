package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.ProfileSourceMode

/** Synthetic presentation only; never observes or changes an application owner/runtime. */
internal class AndroidVisualCaptureFrame(val state: MainUiState, val locations: AndroidLocationVisualState)

internal fun androidVisualCaptureFrame(state: MainUiState): AndroidVisualCaptureFrame {
    val selected = LocationConfigs.normalizeStoredReference(state.selectedProfileRawLink)
    val frameState = if (state.currentScreen == AppScreen.LOCATIONS && selected.isNotBlank() &&
        state.currentLocations.any { LocationConfigs.normalizeStoredReference(it) == selected }
    ) {
        state.copy(
            currentLocations = state.currentLocations.map(LocationConfigs::normalizeStoredReference),
            selectedProfileJson = selected,
            locationBenchmarkDetails = state.locationBenchmarkDetails.mapKeys {
                LocationConfigs.normalizeStoredReference(it.key)
            },
        )
    } else state
    val reference = frameState.selectedProfileRawLink.ifBlank { frameState.selectedProfileJson }
    return AndroidVisualCaptureFrame(frameState, AndroidLocationVisualState(
        activeLocationKey = reference.takeIf { frameState.isVpnRunning && it.isNotBlank() }?.let {
            androidLocationVisualKey(it, if (frameState.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) "" else frameState.selectedProfileSourceUrl)
        },
        restartRequired = frameState.homeSshRestartPending && frameState.isVpnRunning,
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
