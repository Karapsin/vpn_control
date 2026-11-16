package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertSame
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

    @Test
    fun lostTrayShowsTheWindowAndComesBackWithoutHidingIt() {
        val hidden = initialDesktopTrayWindowState(
            startInTray = true,
            traySupported = true,
        ).withTrayAvailable()
        assertFalse(hidden.windowVisible)

        val lost = hidden.withTrayLost()

        assertTrue(lost.windowVisible)
        assertFalse(lost.canHideToTray)
        assertTrue(lost.traySupported)
        assertTrue(lost.withHideWindowRequested().windowVisible)
        assertTrue(lost.withCloseRequestHiddenToTray().windowVisible)

        val back = lost.withTrayAvailable()

        assertTrue(back.canHideToTray)
        assertTrue(back.windowVisible)
    }

    @Test
    fun closeOrHideNeedsTheTrayHostAtThatMoment() {
        val available = initialDesktopTrayWindowState(
            startInTray = false,
            traySupported = true,
        ).withTrayAvailable()

        assertTrue(available.canHideToTrayNow(trayHostPresent = true))
        assertFalse(available.canHideToTrayNow(trayHostPresent = false))
        assertFalse(
            initialDesktopTrayWindowState(startInTray = false, traySupported = true)
                .canHideToTrayNow(trayHostPresent = true),
        )
        assertFalse(available.withTrayUnavailable().canHideToTrayNow(trayHostPresent = true))
    }

    @Test
    fun onlyWindowsAsksTheNotificationArea() {
        assertSame(WindowsNotificationArea, desktopTrayHost(DesktopTrayPlatform.Windows))
        for (platform in listOf(DesktopTrayPlatform.Linux, DesktopTrayPlatform.MacOs, DesktopTrayPlatform.Other)) {
            assertTrue(desktopTrayHost(platform).present(), "$platform keeps its backend's own confirmation")
        }
    }
}
