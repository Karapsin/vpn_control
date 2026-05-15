package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopTrayWindowStateTest {
    @Test
    fun autostartKeepsWindowVisibleUntilTrayIsAvailable() {
        val initial = initialDesktopTrayWindowState(
            startInTray = true,
            traySupported = true,
        )

        assertTrue(initial.windowVisible)
        assertFalse(initial.canHideToTray)

        val available = initial.withTrayAvailable()

        assertFalse(available.windowVisible)
        assertTrue(available.canHideToTray)
    }

    @Test
    fun hideRequestCannotHideBeforeTrayIsAvailable() {
        val state = initialDesktopTrayWindowState(
            startInTray = false,
            traySupported = true,
        ).withHideWindowRequested()

        assertTrue(state.windowVisible)
        assertFalse(state.canHideToTray)
    }

    @Test
    fun closeRequestCanHideOnlyAfterTrayIsAvailable() {
        val beforeTray = initialDesktopTrayWindowState(
            startInTray = false,
            traySupported = true,
        ).withCloseRequestHiddenToTray()

        assertTrue(beforeTray.windowVisible)

        val afterTray = beforeTray
            .withTrayAvailable()
            .withCloseRequestHiddenToTray()

        assertFalse(afterTray.windowVisible)
    }

    @Test
    fun trayUnavailableForcesWindowVisibleAndDisablesFutureHides() {
        val state = initialDesktopTrayWindowState(
            startInTray = true,
            traySupported = true,
        )
            .withTrayAvailable()
            .withTrayUnavailable()
            .withHideWindowRequested()

        assertTrue(state.windowVisible)
        assertFalse(state.traySupported)
        assertFalse(state.trayAvailable)
        assertFalse(state.canHideToTray)
    }
}
