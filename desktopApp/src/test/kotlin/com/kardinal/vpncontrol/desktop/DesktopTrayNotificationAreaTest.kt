package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Native row windows-proxy-lifecycle.no-tray-close, run 6c7250f6 on 2.2.17: the GUI ran on a desktop with no
 * Shell_TrayWnd, AWT took its tray icon there (its SunAwtTrayIcon window was listed), the product took that for an
 * available tray, and the row's gui hide, 75 s after the window appeared, answered OK and hid the only window
 * (gui-hidden-without-usable-tray). The world here is such a desktop on a virtual clock: AWT takes and lists every
 * icon, as the JDK's tray peer does whatever Shell_NotifyIcon answered, and the notification area is a switch. The
 * product's callbacks drive Main.kt's window state as DesktopApplication drives it.
 */
class DesktopTrayNotificationAreaTest {
    @Test
    fun aGuiOnADesktopWithoutANotificationAreaNeverHidesItsWindowAndItsCloseDetaches() {
        val world = WindowsTrayWorld(areaPresent = false)
        world.registration.start()
        // The row's settle is 75 s; gui hide and a close read canHideToTrayNow, which must stay false throughout.
        val hideable = (0..75).filter { second ->
            world.clock.advanceTo(second * 1_000L)
            world.closeHides()
        }
        assertEquals(emptyList(), hideable, "seconds at which gui hide or a close would have hidden the window")
        assertTrue(world.state.windowVisible)
        assertEquals(listOf(59_000L to "unavailable"), world.reports, "unavailable at the 60th attempt, never available")
        assertEquals(emptyList(), world.offered, "no icon is offered where there is no notification area")
        assertFalse(world.state.traySupported)
        assertEquals(0, world.clock.pending, "nothing runs after the last attempt")
    }

    @Test
    fun anAutostartedGuiStaysVisibleUntilTheNotificationAreaExistsAndHidesOnlyThen() {
        val world = WindowsTrayWorld(areaPresent = false, startInTray = true)
        world.registration.start()
        world.clock.advanceTo(9_000)
        assertTrue(world.state.windowVisible, "Explorer's taskbar is not there yet, so the window stays visible")
        assertEquals(emptyList(), world.reports)
        assertEquals(emptyList(), world.offered)
        world.areaPresent = true
        world.clock.advanceTo(10_000)
        assertEquals(listOf(10_000L), world.offered, "the next attempt offers the icon")
        assertEquals(listOf(10_000L to "available"), world.reports)
        assertFalse(world.state.windowVisible, "the autostart hides once the tray is there")
        assertTrue(world.closeHides())
    }

    @Test
    fun aWindowHiddenInTheTrayIsShownWhenTheNotificationAreaGoesAwayAndTheTrayComesBackWithIt() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.registration.start()
        world.clock.advanceTo(0)
        assertTrue(world.closeHides())
        world.state = world.state.withCloseRequestHiddenToTray()
        assertFalse(world.state.windowVisible)
        world.areaPresent = false // Explorer ended.
        world.clock.advanceTo(1_000)
        assertTrue(world.state.windowVisible, "with no notification area the hidden window is shown")
        assertFalse(world.closeHides())
        assertTrue(world.state.traySupported, "the tray waits for the notification area to come back")
        assertEquals(listOf("icon-1"), world.listed, "AWT keeps its icon and adds it again on TaskbarCreated")
        world.areaPresent = true // The new Explorer's taskbar.
        world.clock.advanceTo(3_000)
        assertEquals(listOf(0L to "available", 1_000L to "lost", 2_000L to "available"), world.reports)
        assertTrue(world.closeHides())
        assertTrue(world.state.windowVisible, "nothing hides by itself once the tray is back")
        assertEquals(listOf(0L), world.offered, "one icon throughout")
    }

    @Test
    fun aCloseOrAGuiHideReadsTheNotificationAreaAtThatMoment() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.registration.start()
        world.clock.advanceTo(0)
        world.areaPresent = false // Explorer ended after the watch's last read.
        assertTrue(world.state.canHideToTray, "the watch has not read the notification area again yet")
        assertFalse(world.closeHides(), "so the close detaches and gui hide answers UNSUPPORTED")
    }

    @Test
    fun aDesktopWithANotificationAreaHasItsTrayAtTheFirstAttempt() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.registration.start()
        world.clock.advanceTo(30_000)
        assertEquals(listOf(0L to "available"), world.reports)
        assertEquals(listOf(0L), world.offered)
        assertEquals("icon-1", world.registration.installedIcon)
        assertTrue(world.closeHides())
    }

    @Test
    fun anIconRefusedWhileTheNotificationAreaExistsEndsUnavailableAfterTheLastAttempt() {
        val world = WindowsTrayWorld(areaPresent = true, awtTakes = false)
        world.registration.start()
        world.clock.advanceTo(75_000)
        assertEquals(listOf(59_000L to "unavailable"), world.reports)
        assertEquals(60, world.offered.size)
        assertTrue(world.state.windowVisible)
        assertFalse(world.closeHides())
    }

    @Test
    fun disposeStopsTheWatchAndRemovesTheIcon() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.registration.start()
        world.clock.advanceTo(5_000)
        world.registration.dispose()
        assertEquals(emptyList(), world.listed)
        assertEquals(0, world.clock.pending)
        world.areaPresent = false
        world.clock.advanceTo(10_000)
        assertEquals(listOf(0L to "available"), world.reports)
    }

    @Test
    fun onlyWindowsAsksTheNotificationArea() {
        assertSame(WindowsNotificationArea, desktopTrayHost(DesktopTrayPlatform.Windows))
        for (platform in listOf(DesktopTrayPlatform.Linux, DesktopTrayPlatform.MacOs, DesktopTrayPlatform.Other)) {
            assertTrue(desktopTrayHost(platform).present(), "$platform keeps its backend's own confirmation")
        }
    }
}

/** The product's Windows tray registration on one desktop, with AWT, Explorer's notification area and the window state. */
private class WindowsTrayWorld(
    var areaPresent: Boolean,
    startInTray: Boolean = false,
    private val awtTakes: Boolean = true,
) {
    val clock = NotificationAreaClock()
    val offered = mutableListOf<Long>()
    val listed = mutableListOf<String>()
    val reports = mutableListOf<Pair<Long, String>>()
    var state = initialDesktopTrayWindowState(startInTray = startInTray, traySupported = true)
    val area = DesktopTrayHost { areaPresent }

    /** java.awt.SystemTray as AwtTrayRegistrationTarget meets it on Windows: add returns and lists the icon. */
    private val awt = object : TrayRegistrationTarget<String> {
        override fun install(): TrayInstallResult<String> {
            val icon = "icon-${offered.size + 1}"
            offered += clock.now
            if (!awtTakes) return TrayInstallResult.RetryableFailure
            listed += icon
            return TrayInstallResult.Installed(icon)
        }

        override fun remove(icon: String) {
            listed.remove(icon)
        }
    }

    val registration = NotificationAreaTrayRegistration(
        target = awt,
        area = area,
        scheduler = clock,
        onAvailable = {
            reports += clock.now to "available"
            state = state.withTrayAvailable()
        },
        onUnavailable = {
            reports += clock.now to "unavailable"
            state = state.withTrayUnavailable()
        },
        onLost = {
            reports += clock.now to "lost"
            state = state.withTrayLost()
        },
    )

    /** Main.kt: a close hides into the tray only when this holds and detaches otherwise; gui hide refuses otherwise. */
    fun closeHides(): Boolean = state.canHideToTrayNow(area.present())
}

/** Swing's one-shot timers on a virtual clock: each action runs at its time, in the order it was scheduled. */
private class NotificationAreaClock : TrayRetryScheduler {
    private class Task(val at: Long, val order: Long, val action: () -> Unit) : TrayRetryHandle {
        var cancelled = false

        override fun cancel() {
            cancelled = true
        }
    }

    private val tasks = mutableListOf<Task>()
    private var order = 0L

    var now = 0L
        private set

    val pending: Int
        get() = tasks.count { !it.cancelled }

    override fun schedule(delayMillis: Int, action: () -> Unit): TrayRetryHandle {
        return Task(now + delayMillis, order++, action).also { tasks += it }
    }

    /** Runs every action due up to [time], as the timers would have fired them, and leaves the clock there. */
    fun advanceTo(time: Long) {
        while (true) {
            val next = tasks
                .filter { !it.cancelled && it.at <= time }
                .minWithOrNull(compareBy<Task>({ it.at }, { it.order }))
                ?: break
            tasks.remove(next)
            now = next.at
            next.action()
        }
        tasks.removeAll { it.cancelled }
        now = time
    }
}
