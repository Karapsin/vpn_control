package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import org.junit.Assert.*
import org.junit.Test

class AndroidVisualLocationFixtureTest {
    @Test fun syntheticSelectedSceneUsesCanonicalRowAndItsOwnActiveProjection() {
        val raw = "socks://127.0.0.1:1080#Berlin"
        val state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(raw), selectedProfileRawLink = raw, selectedProfileJson = "{\"outbounds\":[]}",
            selectedProfileSourceUrl = "https://fixture.invalid", locationBenchmarkDetails = mapOf(raw to "tcp=42ms"))
        val fixture = androidSelectedLocationVisualFixture(state)
        val frame = androidVisualCaptureFrame(fixture)
        val row = androidLocationRows(frame.state, AppStrings(AppLanguage.ENGLISH), frame.locations).single()
        assertEquals(LocationConfigs.normalizeStoredReference(raw), fixture.selectedProfileJson)
        assertTrue(row.isSelected)
        assertEquals(true, row.selection?.selected)
        assertEquals(true, row.selection?.active)
        assertEquals("tcp=42ms", row.benchmarkDetail)
        assertEquals(false, frame.locations.restartRequired)
        assertFalse(state.isVpnRunning)
        assertEquals("{\"outbounds\":[]}", state.selectedProfileJson)
    }

    @Test fun stoppedSyntheticSceneHasNoActiveRowEvenWhenAnotherFrameWasRunning() {
        val running = MainUiState(isVpnRunning = true, selectedProfileRawLink = "socks://127.0.0.1:1080#A")
        assertNotNull(androidVisualCaptureFrame(running).locations.activeLocationKey)
        val stopped = androidVisualCaptureFrame(running.copy(isVpnRunning = false, homeSshRestartPending = true))
        assertNull(stopped.locations.activeLocationKey)
        assertEquals(false, stopped.locations.restartRequired)
    }
}
