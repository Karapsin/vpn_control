package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopLocationServiceTest {
    @Test
    fun deleteSelectedLocationKeepsStoppedStateAfterRuntimeStop() = runTest {
        var state = MainUiState(
            appMode = AppMode.VPN,
            isVpnRunning = true,
            selectedProfileName = "Netherlands",
            selectedProfileServer = "nl.example.net",
            selectedProfileRawLink = "vless://selected",
        )
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://selected", isSelected = true),
        )
        val service = DesktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            currentRuntimeMode = { AppMode.VPN },
            stopConnection = {
                state = state.copy(isVpnRunning = false).withStatus("VPN stopped")
                Result.success(Unit)
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.deleteLocation(1)

        assertFalse(state.isVpnRunning)
        assertEquals("", state.selectedProfileName)
        assertEquals("", state.selectedProfileServer)
        assertEquals("", state.selectedProfileRawLink)
        assertTrue(locations.isEmpty())
        assertEquals(StatusMessages.locationRemoved("Netherlands"), state.statusMessage)
    }

    @Test
    fun selectLocationUpdatesSelectedProfileFields() {
        var state = MainUiState()
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://first", name = "First"),
            desktopLocation(index = 2, rawLink = "vless://second", name = "Second"),
        )
        val service = DesktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            currentRuntimeMode = { null },
            stopConnection = { Result.success(Unit) },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.applySelection(2)

        assertEquals("Second", state.selectedProfileName)
        assertEquals("second.example.net", state.selectedProfileServer)
        assertEquals("vless://second", state.selectedProfileRawLink)
        assertFalse(locations[0].isSelected)
        assertTrue(locations[1].isSelected)
        assertEquals(StatusMessages.selectedLocationSet("Second"), state.statusMessage)
    }

    @Test
    fun importRawReportsStructuredBlockedStatusInSubscriptionMode() = runTest {
        var state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION)
        var locations = emptyList<DesktopLocationRecord>()
        val service = DesktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            currentRuntimeMode = { null },
            stopConnection = { Result.success(Unit) },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.importRaw("not relevant")

        assertEquals(StatusMessages.importLocationsBlocked(), state.statusMessage)
    }
}

private fun desktopLocation(
    index: Int,
    rawLink: String,
    name: String = "Netherlands",
    server: String = "${name.lowercase()}.example.net",
    isSelected: Boolean = false,
): DesktopLocationRecord {
    return DesktopLocationRecord(
        index = index,
        sourceUrl = "",
        rawLink = rawLink,
        name = name,
        server = server,
        details = "VLESS TCP",
        benchmarkDetail = "not checked",
        isValid = true,
        isSelected = isSelected,
    )
}
