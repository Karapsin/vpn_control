package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopLocationServiceTest {
    @Test
    fun selectingAlreadySelectedLocationDoesNotPersistAgain() {
        val location = desktopLocation(index = 17, rawLink = "vless://same", name = "Same", isSelected = true)
        val state = MainUiState(
            currentLocations = listOf(location.rawLink), selectedProfileName = location.name,
            selectedProfileServer = location.server, selectedProfileRawLink = location.rawLink,
            selectedProfileSourceUrl = location.sourceUrl, isVpnRunning = true,
        )
        var commits = 0
        val service = desktopLocationService(
            stateProvider = { state }, locationsProvider = { listOf(location) },
            commitState = { _, _ -> commits++ }, updateState = { error("Unexpected status mutation") },
        )

        service.applySelection(location.index)
        assertTrue(service.applyCliSelection("Same").isSuccess)

        assertEquals(0, commits)
    }

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
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
        )

        service.deleteLocation(1)

        assertFalse(state.isVpnRunning)
        assertEquals("", state.selectedProfileName)
        assertEquals("", state.selectedProfileServer)
        assertEquals("", state.selectedProfileRawLink)
        assertTrue(locations.isEmpty())
        assertEquals(LocationStatusMessages.locationRemoved("Netherlands"), state.statusMessage)
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
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
        )

        service.applySelection(2)

        assertEquals("Second", state.selectedProfileName)
        assertEquals("second.example.net", state.selectedProfileServer)
        assertEquals("vless://second", state.selectedProfileRawLink)
        assertFalse(locations[0].isSelected)
        assertTrue(locations[1].isSelected)
        assertEquals(ConnectionStatusMessages.selectedLocationSet("Second"), state.statusMessage)
    }

    @Test
    fun cliSelectLocationUsesExactVisibleName() {
        var state = MainUiState(
            currentLocations = listOf("vless://first", "vless://second"),
        )
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://first", name = "First"),
            desktopLocation(index = 2, rawLink = "vless://second", name = "Second"),
        )
        val service = desktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        val result = service.applyCliSelection("Second")

        assertTrue(result.isSuccess)
        assertEquals("Second", result.getOrThrow().name)
        assertEquals("Second", state.selectedProfileName)
        assertTrue(locations[1].isSelected)
    }

    @Test
    fun cliSelectLocationUsesOneBasedVisibleIndexWhenNameDoesNotMatch() {
        var state = MainUiState(
            currentLocations = listOf("vless://second", "vless://third"),
        )
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://first", name = "First"),
            desktopLocation(index = 2, rawLink = "vless://second", name = "Second"),
            desktopLocation(index = 3, rawLink = "vless://third", name = "Third"),
        )
        val service = desktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        val result = service.applyCliSelection("2")

        assertTrue(result.isSuccess)
        assertEquals("Third", result.getOrThrow().name)
        assertEquals("Third", state.selectedProfileName)
        assertFalse(locations[1].isSelected)
        assertTrue(locations[2].isSelected)
    }

    @Test
    fun cliSelectLocationFailsOnDuplicateVisibleNames() {
        var state = MainUiState(
            currentLocations = listOf("vless://first", "vless://second"),
        )
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://first", name = "Duplicate"),
            desktopLocation(index = 2, rawLink = "vless://second", name = "Duplicate"),
        )
        val service = desktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        val result = service.applyCliSelection("Duplicate")

        assertTrue(result.isFailure)
        assertEquals("", state.selectedProfileName)
        assertEquals(com.kardinal.vpncontrol.model.ConnectionStatusMessages.selectedLocationSelectFailed(), state.statusMessage)
        assertFalse(locations.any { it.isSelected })
    }

    @Test
    fun cliSelectLocationFailsWhenTargetIsMissing() {
        var state = MainUiState(
            currentLocations = listOf("vless://first"),
        )
        var locations = listOf(
            desktopLocation(index = 1, rawLink = "vless://first", name = "First"),
        )
        val service = desktopLocationService(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        val result = service.applyCliSelection("Missing")

        assertTrue(result.isFailure)
        assertEquals("", state.selectedProfileName)
        assertEquals(com.kardinal.vpncontrol.model.ConnectionStatusMessages.selectedLocationSelectFailed(), state.statusMessage)
        assertFalse(locations.single().isSelected)
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
                Result.success(Unit)
            },
            updateState = { transform -> state = transform(state) },
        )

        service.importRaw("not relevant")

        assertEquals(LocationStatusMessages.importLocationsBlocked(), state.statusMessage)
    }

    private fun desktopLocationService(
        stateProvider: () -> MainUiState,
        locationsProvider: () -> List<DesktopLocationRecord>,
        commitState: (MainUiState, List<DesktopLocationRecord>) -> Unit,
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): DesktopLocationService {
        return DesktopLocationService(
            stateProvider = stateProvider,
            locationsProvider = locationsProvider,
            currentRuntimeMode = { null },
            stopConnection = { Result.success(Unit) },
            commitState = { state, locations -> commitState(state, locations); Result.success(Unit) },
            updateState = updateState,
        )
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
