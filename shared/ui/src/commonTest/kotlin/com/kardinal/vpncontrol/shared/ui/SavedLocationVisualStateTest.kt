package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.MainUiState
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SavedLocationVisualStateTest {
    @Test
    fun diagnosticsNeverDisableManualLocationActions() {
        assertTrue(savedLocationManualActionEnabled(appEnabled = true, autoSelectable = false))
        assertFalse(savedLocationManualActionEnabled(appEnabled = false, autoSelectable = true))
    }

    @Test
    fun runningMatchingSelectionShowsInUseAndTogglesConnection() {
        val location = row(rawLink = "stored-selected")
        val visualState = savedLocationVisualState(
            location = location,
            state = MainUiState(
                isVpnRunning = true,
                selectedProfileRawLink = location.rawLink,
            ),
        )

        assertTrue(visualState.isSelected)
        assertTrue(visualState.isInUse)
        assertTrue(visualState.togglesConnection)
    }

    @Test
    fun runningStaleSelectedFlagDoesNotShowInUseOrToggleConnection() {
        val visualState = savedLocationVisualState(
            location = row(
                rawLink = "stored-stale",
                isSelected = true,
            ),
            state = MainUiState(
                isVpnRunning = true,
                selectedProfileRawLink = "stored-active",
            ),
        )

        assertFalse(visualState.isSelected)
        assertFalse(visualState.isInUse)
        assertFalse(visualState.togglesConnection)
    }

    @Test
    fun stoppedSelectedLocationShowsSelectedAndStartsConnection() {
        val location = row(rawLink = "stored-selected")
        val visualState = savedLocationVisualState(
            location = location,
            state = MainUiState(selectedProfileRawLink = location.rawLink),
        )

        assertTrue(visualState.isSelected)
        assertFalse(visualState.isInUse)
        assertTrue(visualState.togglesConnection)
    }

    @Test
    fun runningWithoutVisibleMatchShowsNoSelectedState() {
        val visualState = savedLocationVisualState(
            location = row(rawLink = "stored-visible"),
            state = MainUiState(
                isVpnRunning = true,
                selectedProfileRawLink = "stored-missing",
            ),
        )

        assertFalse(visualState.isSelected)
        assertFalse(visualState.isInUse)
        assertFalse(visualState.togglesConnection)
    }

    private fun row(
        rawLink: String,
        isSelected: Boolean = false,
    ): SavedLocationRow {
        return SavedLocationRow(
            index = 0,
            rawLink = rawLink,
            name = "Location",
            server = "127.0.0.1",
            details = "SOCKS",
            benchmarkDetail = "",
            autoSelectable = true,
            isSelected = isSelected,
        )
    }
}
