package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Native row windows-proxy-lifecycle.no-tray-close, run 6c7250f6 on 2.2.17: the GUI ran on a desktop with no
 * Shell_TrayWnd, AWT took its tray icon there (its SunAwtTrayIcon window was listed), the product took that for an
 * available tray, and the row's gui hide, 75 s after the window appeared, answered OK and hid the only window
 * (gui-hidden-without-usable-tray). The world here is such a desktop on a virtual clock: AWT takes and lists every
 * icon, as the JDK's tray peer does whatever Shell_NotifyIcon answered, and the notification area is a switch.
 *
 * Everything between AWT and the window runs as the product runs it: DesktopTrayIcon's [startDesktopTray] with the
 * installer, the AWT backend's [AwtTrayRegistration] (its decision, with only java.awt.SystemTray replaced) and
 * Main.kt's [DesktopTrayWindow], whose close and gui show/hide decisions DesktopApplication's handlers call.
 */
class DesktopTrayNotificationAreaTest {
    @Test
    fun aGuiOnADesktopWithoutANotificationAreaNeverHidesItsWindowAndItsCloseDetaches() {
        val world = WindowsTrayWorld(areaPresent = false)
        world.start()
        // The row's settle is 75 s; at every second a gui hide must be refused and a close must detach.
        val hidden = (0..75).filter { second ->
            world.clock.advanceTo(second * 1_000L)
            world.guiHideHides() or world.closeHides()
        }
        assertEquals(emptyList(), hidden, "seconds at which gui hide or a close hid the window")
        assertTrue(world.state.windowVisible)
        assertEquals(emptyList(), world.reports, "never available, and not given up either: the area may still come")
        assertEquals(emptyList(), world.offered, "no icon is offered where there is no notification area")
        assertTrue(world.state.traySupported)
        assertEquals(1, world.clock.pending, "the notification area is still read every second")
    }

    @Test
    fun aNotificationAreaThatAppearsLongAfterTheGuiStartedStillGetsTheTray() {
        // Autostart is an ONLOGON task that does not wait for Explorer; its taskbar can come minutes later.
        val world = WindowsTrayWorld(areaPresent = false, startInTray = true)
        world.start()
        world.clock.advanceTo(89_000)
        assertEquals(emptyList(), world.reports, "no tray yet, and none given up")
        assertTrue(world.state.traySupported)
        assertTrue(world.state.windowVisible)
        assertFalse(world.guiHideHides())
        world.areaPresent = true
        world.clock.advanceTo(90_000)
        assertEquals(listOf(90_000L), world.offered, "the icon is offered at the first read that finds the area")
        assertEquals(listOf(90_000L to "available"), world.reports)
        assertFalse(world.state.windowVisible, "the autostart hides once the tray is there")
        world.window.guiVisibility(shown = true)
        assertTrue(world.closeHides())
    }

    @Test
    fun anAutostartedGuiStaysVisibleUntilTheNotificationAreaExistsAndHidesOnlyThen() {
        val world = WindowsTrayWorld(areaPresent = false, startInTray = true)
        world.start()
        world.clock.advanceTo(9_000)
        assertTrue(world.state.windowVisible, "Explorer's taskbar is not there yet, so the window stays visible")
        assertEquals(emptyList(), world.reports)
        assertEquals(emptyList(), world.offered)
        world.areaPresent = true
        world.clock.advanceTo(10_000)
        assertEquals(listOf(10_000L), world.offered, "the next read offers the icon")
        assertEquals(listOf(10_000L to "available"), world.reports)
        assertFalse(world.state.windowVisible, "the autostart hides once the tray is there")
    }

    @Test
    fun aWindowHiddenInTheTrayIsShownWhenTheNotificationAreaGoesAwayAndTheTrayComesBackWithIt() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.start()
        world.clock.advanceTo(0)
        assertTrue(world.window.closeToTray(), "a close hides into the tray")
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
        assertTrue(world.state.windowVisible, "nothing hides by itself once the tray is back")
        assertTrue(world.closeHides())
        assertEquals(listOf(0L), world.offered, "one icon throughout")
    }

    @Test
    fun aCloseOrAGuiHideReadsTheNotificationAreaAtThatMoment() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.start()
        world.clock.advanceTo(0)
        world.areaPresent = false // Explorer ended after the watch's last read.
        assertTrue(world.state.canHideToTray, "the watch has not read the notification area again yet")
        assertFalse(world.window.guiVisibility(shown = false), "gui hide answers UNSUPPORTED")
        assertFalse(world.window.closeToTray(), "the close detaches")
        assertTrue(world.state.windowVisible)
    }

    @Test
    fun aDesktopWithANotificationAreaHasItsTrayAtTheFirstAttempt() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.start()
        world.clock.advanceTo(30_000)
        assertEquals(listOf(0L to "available"), world.reports)
        assertEquals(listOf(0L), world.offered)
        assertEquals(listOf("icon-1"), world.listed)
        assertTrue(world.guiHideHides())
        assertTrue(world.closeHides())
    }

    @Test
    fun anIconRefusedWhileTheNotificationAreaExistsEndsUnavailableAfterTheLastAttempt() {
        val world = WindowsTrayWorld(areaPresent = true, awtTakes = false)
        world.start()
        world.clock.advanceTo(75_000)
        assertEquals(listOf(59_000L to "unavailable"), world.reports)
        assertEquals(60, world.offered.size)
        assertFalse(world.state.traySupported)
        assertTrue(world.state.windowVisible)
        assertFalse(world.closeHides())
    }

    @Test
    fun stoppingTheTrayStopsTheWatchAndRemovesTheIcon() {
        val world = WindowsTrayWorld(areaPresent = true)
        world.start()
        world.clock.advanceTo(5_000)
        world.stop()
        assertEquals(emptyList(), world.listed)
        assertEquals(0, world.clock.pending)
        world.areaPresent = false
        world.clock.advanceTo(10_000)
        assertEquals(listOf(0L to "available"), world.reports)
    }

    @Test
    fun onMacOsTheIconAwtTakesIsTheTrayWhateverTheWindowsAreaSays() {
        val world = WindowsTrayWorld(areaPresent = false, platform = DesktopTrayPlatform.MacOs)
        world.start()
        world.clock.advanceTo(5_000)
        assertEquals(listOf(0L to "available"), world.reports)
        assertTrue(world.closeHides(), "Main.kt's host is always present off Windows; this world's switch is Windows'")
    }

    @Test
    fun onLinuxTheRegistrationLeavesTheDecisionToTheVisibilityMonitor() {
        val world = WindowsTrayWorld(areaPresent = true, platform = DesktopTrayPlatform.Linux)
        world.start()
        world.clock.advanceTo(5_000)
        assertEquals(listOf(0L), world.offered)
        assertEquals(emptyList(), world.reports, "AwtTrayHandle's monitor, which needs X11, reports Linux availability")
    }
}

/**
 * One GUI's tray on one desktop: AWT, Explorer's notification area and the window, wired as DesktopTrayIcon,
 * AwtTrayBackend and DesktopApplication wire them, on [platform].
 */
private class WindowsTrayWorld(
    var areaPresent: Boolean,
    startInTray: Boolean = false,
    private val awtTakes: Boolean = true,
    private val platform: DesktopTrayPlatform = DesktopTrayPlatform.Windows,
) {
    val clock = NotificationAreaClock()
    val offered = mutableListOf<Long>()
    val listed = mutableListOf<String>()
    val reports = mutableListOf<Pair<Long, String>>()
    val area = DesktopTrayHost { areaPresent }

    /** Main.kt's window; on Windows its tray host is the notification area, elsewhere always there (desktopTrayHost). */
    val window = DesktopTrayWindow(
        initial = initialDesktopTrayWindowState(startInTray = startInTray, traySupported = true),
        trayHost = if (platform == DesktopTrayPlatform.Windows) area else DesktopTrayHost { true },
    )

    val state: DesktopTrayWindowState
        get() = window.state

    private var stopTray: () -> Unit = {}

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

    /** AwtTrayBackend.install with this world's AWT, notification area and clock in place of AWT's and Swing's. */
    private val backend = object : DesktopTrayBackend {
        override fun install(
            appTitle: () -> String,
            menuState: () -> TrayMenuState,
            onAvailable: () -> Unit,
            onUnavailable: () -> Unit,
            onLost: () -> Unit,
        ): DesktopTrayHandle {
            lateinit var handle: DesktopTrayHandle
            val registration = AwtTrayRegistration(
                platform = platform,
                target = awt,
                area = area,
                scheduler = clock,
                retryPolicy = TrayRegistrationRetryPolicy(),
                onAvailable = onAvailable,
                onUnavailable = onUnavailable,
                onLost = onLost,
                beforeUnavailable = { handle.dispose() },
                onIconInstalled = {},
            )
            handle = object : DesktopTrayHandle {
                override fun update(appTitle: String, menuState: TrayMenuState) = Unit

                override fun dispose() = registration.dispose()
            }
            registration.start()
            return handle
        }
    }

    /** What reaches Main.kt's window, recorded on the way. */
    private val events = object : DesktopTrayEvents {
        override fun onTrayAvailable() {
            reports += clock.now to "available"
            window.onTrayAvailable()
        }

        override fun onTrayUnavailable() {
            reports += clock.now to "unavailable"
            window.onTrayUnavailable()
        }

        override fun onTrayLost() {
            reports += clock.now to "lost"
            window.onTrayLost()
        }
    }

    /** DesktopTrayIcon entering the composition; the worker and the event thread run in place on the clock. */
    fun start() {
        stopTray = startDesktopTray(
            installer = AsyncDesktopTrayBackendInstaller(
                installer = DesktopTrayBackendInstaller(listOf(backend)),
                launchWorker = { task -> task() },
            ),
            holder = DesktopTrayHandleHolder(),
            appTitle = { "VPN Control" },
            menuState = { worldMenu },
            events = events,
            dispatch = { action -> action() },
        )
    }

    /** DesktopTrayIcon leaving the composition. */
    fun stop() = stopTray()

    /** The gui hide handler's decision now; a window it hid is shown again so the world goes on unchanged. */
    fun guiHideHides(): Boolean {
        val hid = window.guiVisibility(shown = false)
        if (hid) window.guiVisibility(shown = true)
        return hid
    }

    /** onCloseRequest's decision now (false: the close detaches); a window it hid is shown again likewise. */
    fun closeHides(): Boolean {
        val hid = window.closeToTray()
        if (hid) window.guiVisibility(shown = true)
        return hid
    }
}

private val worldMenu = TrayMenuState(
    connectionActionLabel = "Connect",
    findBestLabel = "Find best",
    showWindowLabel = "Show window",
    hideWindowLabel = "Hide window",
    exitLabel = "Exit",
    connectionActionEnabled = true,
    findBestEnabled = true,
    onToggleConnection = {},
    onFindBest = {},
    onShowWindow = {},
    onHideWindow = {},
    onExit = {},
)

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
