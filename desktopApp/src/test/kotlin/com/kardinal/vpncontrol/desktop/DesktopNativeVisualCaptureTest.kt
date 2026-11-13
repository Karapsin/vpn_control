package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.ui.awt.ComposeWindow
import com.sun.jna.Native
import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import dorkbox.systemTray.SystemTray as DorkboxSystemTray
import java.awt.Color
import java.awt.EventQueue
import java.awt.FileDialog
import java.awt.GraphicsEnvironment
import java.awt.Rectangle
import java.awt.Robot
import java.awt.SystemTray
import java.awt.Window
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.imageio.ImageIO
import javax.swing.JWindow
import javax.swing.SwingUtilities
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Test

/**
 * Captures only surfaces owned by the host operating system. The caller must provide an
 * isolated desktop or an ephemeral hosted runner; this test deliberately refuses the
 * operator's ordinary desktop because a full-screen capture could expose private data.
 * Windows scenes are region captures (VISUAL-002): the target surface's own region located by
 * native identity, with the full screen of the same moment kept beside it as diagnostic evidence.
 */
class DesktopNativeVisualCaptureTest {
    private var macosPrivateWindowPermissionPrepared = false

    @Test
    fun nativeWindowRuntimeFixtureMatchesOwnerRenderedMessages() {
        val directory = Files.createTempDirectory("vpn-control-native-visual-runtime-status")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            val declared = nativeVisualRuntimeStatusDetails()
            service.replaceStateForVisualCapture(visualState("main-disconnected"), visualLocations(),
                runtimeStatusDetails = declared)
            val rendered = service.controlPresentationSnapshot("visual-fixture").frontend.activity.runtimeDetails.messages()
            check(declared == rendered) {
                "Native window fixture status $declared differs from owner-rendered status $rendered"
            }
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun nativeVisualRuntimeStatusDetails() = listOf(RuntimeStatusMessages.runtimeMode("VPN"))
    private val robot by lazy {
        Robot().apply {
            autoDelay = 120
            isAutoWaitForIdle = true
        }
    }

    @Test
    fun captureRequestedNativeScenes() {
        if (System.getenv("VPN_CONTROL_VISUAL_OUTPUT") == null) return
        require(
            System.getenv("VPN_CONTROL_VISUAL_PROVIDER") == "hosted" ||
                System.getenv("VPN_CONTROL_VISUAL_ISOLATED") == "1",
        ) {
            "Native visual capture requires an isolated desktop or ephemeral hosted runner"
        }
        require(!GraphicsEnvironment.isHeadless()) { "Native visual capture requires a graphical desktop" }

        val platform = requireNotNull(System.getenv("VPN_CONTROL_VISUAL_PLATFORM"))
        val manifest = Path.of(requireNotNull(System.getenv("VPN_CONTROL_VISUAL_MANIFEST")))
        val output = Path.of(requireNotNull(System.getenv("VPN_CONTROL_VISUAL_OUTPUT")))
        val requested = System.getenv("VPN_CONTROL_VISUAL_NATIVE_SCENES")
            .orEmpty()
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toSet()
        val scenes = nativeScenes(manifest, platform, requested).sortedBy { sceneId ->
            when {
                "tray" in sceneId || "menu-bar" in sceneId -> 0
                sceneId.endsWith("open-dialog") || sceneId.endsWith("save-dialog") -> 2
                else -> 1
            }
        }
        require(scenes.isNotEmpty()) { "No native $platform scenes were requested" }
        Files.createDirectories(output)

        val captureBounds = canonicalCaptureBounds()
        if (platform == "windows") {
            captureWindowsRegionScenes(scenes, output, captureBounds)
            return
        }
        if (System.getenv("VPN_CONTROL_VISUAL_EXTERNAL_FRAMEBUFFER") != "1") {
            prepareScreenCapturePermission(platform)
        }
        scenes.forEach { sceneId ->
            captureScene(platform, sceneId, output.resolve("$sceneId.png"), captureBounds)
        }
    }

    private fun captureScene(platform: String, sceneId: String, output: Path, bounds: Rectangle) {
        when {
            sceneId.endsWith("window-frame") -> withApplicationWindow(sceneId) {
                captureScreen(output, bounds)
            }
            sceneId.endsWith("open-dialog") -> withApplicationWindow(sceneId) { window ->
                captureFileDialog(platform, window, save = false, output = output, bounds = bounds)
            }
            sceneId.endsWith("save-dialog") -> withApplicationWindow(sceneId) { window ->
                captureFileDialog(platform, window, save = true, output = output, bounds = bounds)
            }
            "tray" in sceneId || "menu-bar" in sceneId -> captureTray(sceneId, output, bounds)
            platform == "linux" -> captureLinuxSurface(sceneId, output, bounds)
            platform == "macos" -> captureMacSurface(sceneId, output, bounds)
            else -> error("Unsupported native visual scene: $platform/$sceneId")
        }
    }

    /**
     * Every Windows scene runs under one capture session (caret blink, animations, keyboard cues,
     * transparency and theme pinned, then restored). A refused scene keeps its diagnostic frame
     * and named reason, and the remaining scenes still run before the task fails; a session that
     * cannot be applied refuses every requested scene the same way (runRegionCaptureScenes).
     */
    private fun captureWindowsRegionScenes(scenes: List<String>, output: Path, bounds: Rectangle) {
        require(System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
            "Windows region capture requires a Windows desktop"
        }
        val desktop = WindowsRegionDesktop(robot)
        runRegionCaptureScenes(desktop, "windows", desktop.sessionSettings(), scenes, output) { engine, sceneId ->
            captureWindowsRegionScene(WindowsRegion(desktop, engine), sceneId, output, bounds)
        }
    }

    private class WindowsRegion(val desktop: WindowsRegionDesktop, val engine: RegionCaptureEngine)

    private fun captureWindowsRegionScene(region: WindowsRegion, sceneId: String, output: Path, bounds: Rectangle) {
        when {
            sceneId == "windows-uac" -> refuseRegion(
                sceneId,
                RegionCaptureRefusal.SECURE_DESKTOP,
                "the secure desktop cannot be captured from the user session; crop the owned VM frame with scripts/visual_region.py",
            )
            sceneId.endsWith("window-frame") -> withApplicationWindow(sceneId) { window ->
                captureWindowsApplicationWindow(region, sceneId, window, output)
            }
            sceneId.endsWith("open-dialog") -> withApplicationWindow(sceneId) { window ->
                captureFileDialog("windows", window, save = false, output = output.resolve("$sceneId.png"), bounds = bounds, region = region)
            }
            sceneId.endsWith("save-dialog") -> withApplicationWindow(sceneId) { window ->
                captureFileDialog("windows", window, save = true, output = output.resolve("$sceneId.png"), bounds = bounds, region = region)
            }
            "tray" in sceneId -> captureTray(sceneId, output.resolve("$sceneId.png"), bounds, region)
            sceneId == "windows-msi" -> captureWindowsInstaller(
                region, sceneId, output, listOf("msiexec.exe", "/i", requireVisualPackage(".msi").toString()),
            )
            sceneId == "windows-update-installer" -> captureWindowsInstaller(
                region, sceneId, output, listOf("msiexec.exe", "/i", requireVisualPackage(".msi").toString(), "/norestart"),
            )
            else -> error("Unsupported Windows native scene: $sceneId")
        }
    }

    private fun awtHandle(window: Window): Long = Native.getWindowID(window)

    /** AWT owns its windows' bounds; its bounds on Windows are the window rectangle. */
    private fun awtMover(window: Window): (Long, PlacementMove, Boolean) -> Unit = { _, move, resize ->
        onEventThread {
            val rect = move.windowRect
            if (resize) window.setBounds(rect.left, rect.top, rect.width, rect.height) else window.setLocation(rect.left, rect.top)
        }
    }

    /** Opaque backdrop directly beneath a window part, so its border blends with a fixed colour. */
    private fun withRegionBackdrop(
        region: WindowsRegion,
        sceneId: String,
        part: LocatedPart,
        block: (LocatedPart) -> Unit,
    ) {
        val rect = part.rect.expanded(WindowsRegionScenes.BACKDROP_MARGIN)
        val backdrop = onEventThread {
            JWindow().apply {
                name = "vpn-control-visual-backdrop"
                focusableWindowState = false
                background = Color(WindowsRegionScenes.BACKDROP_RGB)
                contentPane.background = Color(WindowsRegionScenes.BACKDROP_RGB)
                setBounds(rect.left, rect.top, rect.width, rect.height)
                isVisible = true
            }
        }
        try {
            // A refusal keeps the frame of its moment, before the backdrop and the target close.
            region.engine.keepingRefusedMoment {
                val handle = awtHandle(backdrop)
                awaitTarget(
                    sceneId,
                    TargetRule("capture-backdrop", handle = handle, processId = region.desktop.processId),
                    40,
                    region.desktop::census,
                ) { region.desktop.pause(100) }
                block(part.copy(backdropHandle = handle))
            }
        } finally {
            onEventThread {
                backdrop.isVisible = false
                backdrop.dispose()
            }
        }
    }

    private fun captureWindowsApplicationWindow(region: WindowsRegion, sceneId: String, window: ComposeWindow, output: Path) {
        val handle = awtHandle(window)
        val part = region.engine.placeWindow(
            sceneId,
            "application-window",
            TargetRule("application-window", handle = handle, processId = region.desktop.processId),
            WindowsRegionScenes.windowFrame,
            awtMover(window),
        )
        withRegionBackdrop(region, sceneId, part) { backed ->
            region.engine.capture(sceneId, output, listOf(backed), handle)
        }
    }

    private fun captureWindowsFileDialog(region: WindowsRegion, sceneId: String, owner: ComposeWindow, title: String, output: Path) {
        val part = region.engine.placeWindow(
            sceneId,
            "file-dialog",
            TargetRule(
                "file-dialog",
                processId = region.desktop.processId,
                className = WindowsRegionScenes.FILE_DIALOG_CLASS,
                title = title,
                ownerHandle = awtHandle(owner),
            ),
            WindowsRegionScenes.fileDialog,
            region.desktop::moveForeign,
        )
        withRegionBackdrop(region, sceneId, part) { backed ->
            region.engine.capture(sceneId, output, listOf(backed), backed.targetHandle)
        }
    }

    /** The wizard is located by the msiexec process this test started, never by screen position. */
    private fun captureWindowsInstaller(region: WindowsRegion, sceneId: String, output: Path, command: List<String>) {
        val process = checkNotNull(runCommand(command, wait = false))
        val processId = process.pid().toInt()
        try {
            val part = region.engine.placeWindow(
                sceneId,
                "installer-wizard",
                TargetRule("installer-wizard", processId = processId, titleSuffix = WindowsRegionScenes.INSTALLER_TITLE_SUFFIX),
                WindowsRegionScenes.installerWizard,
                region.desktop::moveForeign,
                maxPolls = 240,
            )
            withRegionBackdrop(region, sceneId, part) { backed ->
                region.engine.capture(sceneId, output, listOf(backed), backed.targetHandle)
            }
        } finally {
            if (process.isAlive) {
                process.destroy()
                process.waitFor(30, TimeUnit.SECONDS)
            }
            awaitProcessWindowsClosed(region, processId)
        }
    }

    /** The next scene's occlusion guard must not meet a closing wizard; bounded, never throws. */
    private fun awaitProcessWindowsClosed(region: WindowsRegion, processId: Int) {
        for (poll in 1..40) {
            if (region.desktop.census().none { it.processId == processId && it.paints }) break
            region.desktop.pause(250)
        }
    }

    /**
     * The tray scene is two native surfaces stacked in a fixed layout: the popup menu window
     * moved to its canonical place over a backdrop, then the notification icon's own rectangle
     * (Shell_NotifyIconGetRect). Their union would include the taskbar between them, other icons
     * and possibly the clock, so the union is never captured.
     */
    private fun captureWindowsTray(
        region: WindowsRegion,
        sceneId: String,
        popup: Window,
        helper: Window,
        output: Path,
    ) = region.engine.keepingRefusedMoment {
        val desktop = region.desktop
        val menu = region.engine.placeWindow(
            sceneId,
            "tray-menu",
            TargetRule("tray-menu", handle = awtHandle(popup), processId = desktop.processId),
            WindowsRegionScenes.trayMenu,
            awtMover(popup),
        )
        val icon = SystemTray.getSystemTray().trayIcons.firstOrNull() ?: refuseRegion(
            sceneId, RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE, "no AWT tray icon is installed",
        )
        val id = runCatching { WindowsRegionDesktop.awtTrayIconId(icon) }.getOrElse { error ->
            refuseRegion(sceneId, RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE, "TrayIcon.id is unreadable: ${error.message}")
        }
        // Promotion fails closed and is restored in every outcome; a refusal keeps the frame of its
        // moment before the promotion is restored.
        promoteNotifyIcon(desktop, sceneId, id).use { promotion ->
            region.engine.keepingRefusedMoment {
                val iconPart = locateNotifyIcon(desktop, sceneId, id, promotion)
                withRegionBackdrop(region, sceneId, menu) { backedMenu ->
                    // The helper window takes focus so neither the menu nor the taskbar shows focus.
                    region.engine.capture(sceneId, output, listOf(backedMenu, iconPart), awtHandle(helper))
                }
            }
        }
    }

    private fun withApplicationWindow(sceneId: String, block: (ComposeWindow) -> Unit) {
        val testRoot = Files.createTempDirectory("vpn-control-native-visual-")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(testRoot))
        service.replaceStateForVisualCapture(
            visualState(if ("connected" in sceneId) "main-connected" else "main-disconnected"),
            visualLocations(),
            runtimeStatusDetails = nativeVisualRuntimeStatusDetails(),
        )
        val window = ComposeWindow()
        onEventThread {
            window.apply {
                title = "VPN Control"
                setSize(1000, 720)
                setLocation(140, 40)
                setContent {
                    VisualNativeApp(service = service, window = window)
                }
                isVisible = true
                toFront()
            }
        }
        try {
            waitForVisibleWindow(window)
            activateWindow(window)
            block(window)
        } finally {
            onEventThread {
                window.isVisible = false
                window.dispose()
            }
            testRoot.toFile().deleteRecursively()
        }
    }

    @Composable
    private fun VisualNativeApp(service: DesktopAppService, window: ComposeWindow) {
        VpnControlTheme {
            DesktopVpnControlApp(
                windowProvider = { window },
                service = service,
                onCheckAndDownloadUpdate = {},
                onDismissOrCancelUpdate = {},
                onInstallUpdate = {},
            )
        }
    }

    private fun captureFileDialog(
        platform: String,
        window: ComposeWindow,
        save: Boolean,
        output: Path,
        bounds: Rectangle,
        region: WindowsRegion? = null,
    ) {
        // macOS column view exposes the selected directory's parent. Use a dedicated clean
        // two-level container instead of the shared temp directory so every visible ancestor is
        // deterministic and runner/Gradle files never enter evidence.
        val fixtureRoot = if (platform == "macos") {
            Path.of(System.getProperty("user.home"), ".vpn-control-visual-fixture")
        } else {
            Path.of(System.getProperty("java.io.tmpdir"), "vpn-control-visual-files")
        }
        val fixtureDirectory = if (platform == "macos") {
            fixtureRoot.resolve("container").resolve("vpn-control-visual-files")
        } else {
            fixtureRoot
        }
        fixtureRoot.toFile().deleteRecursively()
        Files.createDirectories(fixtureDirectory)
        val title = if (save) "Export VPN Control diagnostics" else "Import VPN Control configuration"
        val completed = CountDownLatch(1)
        val thread = Thread({
            try {
                FileDialog(
                    window,
                    title,
                    if (save) FileDialog.SAVE else FileDialog.LOAD,
                ).apply {
                    directory = fixtureDirectory.toString()
                    if (save) file = "vpn-control-diagnostics.txt"
                    isVisible = true
                }
            } finally {
                completed.countDown()
            }
        }, "vpn-control-native-file-dialog")
        thread.isDaemon = true
        thread.start()
        val dialog = waitForWindow<FileDialog>()
        try {
            activateWindow(dialog)
            if (region != null) {
                captureWindowsFileDialog(region, output.fileName.toString().removeSuffix(".png"), window, title, output.parent)
            } else {
                captureVisibleSurface(output, bounds)
            }
        } finally {
            onEventThread {
                dialog.isVisible = false
                dialog.dispose()
            }
            check(completed.await(10, TimeUnit.SECONDS)) { "Native file dialog did not close after capture" }
            check(!dialog.isShowing) { "Native file dialog remained visible after capture" }
            // AppKit closes its native sheet asynchronously after AWT has disposed the peer.
            // Let that animation finish before the next independent scene is opened.
            Thread.sleep(2_000)
            fixtureRoot.toFile().deleteRecursively()
        }
    }

    private fun captureTray(sceneId: String, output: Path, bounds: Rectangle, region: WindowsRegion? = null) {
        val connected = "connected" in sceneId && "disconnected" !in sceneId
        val backend = when {
            "tray-awt" in sceneId -> "awt"
            "tray-native" in sceneId -> "native"
            else -> null
        }
        val prior = System.getProperty("vpn.control.linux.trayBackend")
        val priorAutoHide = System.getProperty("vpn.control.trayPopupAutoHideMillis")
        val priorDorkboxTrayType = DorkboxSystemTray.FORCE_TRAY_TYPE
        if (backend != null) System.setProperty("vpn.control.linux.trayBackend", backend)
        System.setProperty("vpn.control.trayPopupAutoHideMillis", "120000")
        if (backend == "native") {
            DorkboxSystemTray.FORCE_TRAY_TYPE = DorkboxSystemTray.TrayType.Gtk
        }
        val available = CountDownLatch(1)
        val window = onEventThread {
            ComposeWindow().apply {
                title = "VPN Control"
                // Keep the tray fixture's helper window out of the full-screen capture. The
                // production tray owns the visible surface; this window only hosts Compose.
                setSize(1, 1)
                setLocation(0, 0)
                setContent {
                    VpnControlTheme {
                        DesktopTrayIcon(
                            appTitle = "VPN Control",
                            connectionActionLabel = if (connected) "Disconnect" else "Connect",
                            findBestLabel = "Find best",
                            showWindowLabel = "Show window",
                            hideWindowLabel = "Hide window",
                            exitLabel = "Exit",
                            connectionActionEnabled = true,
                            findBestEnabled = !connected,
                            onToggleConnection = {},
                            onFindBest = {},
                            onShowWindow = {},
                            onHideWindow = {},
                            onExit = {},
                            onTrayAvailable = available::countDown,
                        )
                    }
                }
                isVisible = true
            }
        }
        var awtPopup: Window? = null
        try {
            check(available.await(30, TimeUnit.SECONDS)) { "The production tray backend did not become available" }
            if (region == null) preparePrivateWindowCapturePermission(bounds)
            if (backend == "native") openNativeTrayMenuWhenAvailable()
            else awtPopup = openAwtTrayMenuWhenAvailable(sceneId, bounds)
            Thread.sleep(300)
            check(awtPopup == null || awtPopup.isShowing) { "VPN Control tray menu closed before capture" }
            if (region != null) {
                captureWindowsTray(region, sceneId, checkNotNull(awtPopup), window, output.parent)
            } else {
                captureVisibleSurface(output, bounds)
            }
            check(awtPopup == null || awtPopup.isShowing) { "VPN Control tray menu closed during capture" }
        } finally {
            awtPopup?.let { popup ->
                onEventThread {
                    popup.isVisible = false
                    popup.dispose()
                }
            }
            onEventThread {
                window.isVisible = false
                window.dispose()
            }
            if (prior == null) System.clearProperty("vpn.control.linux.trayBackend")
            else System.setProperty("vpn.control.linux.trayBackend", prior)
            if (priorAutoHide == null) System.clearProperty("vpn.control.trayPopupAutoHideMillis")
            else System.setProperty("vpn.control.trayPopupAutoHideMillis", priorAutoHide)
            DorkboxSystemTray.FORCE_TRAY_TYPE = priorDorkboxTrayType
        }
    }

    private fun openAwtTrayMenuWhenAvailable(sceneId: String, bounds: Rectangle): Window {
        check(SystemTray.isSupported()) { "AWT system tray is unavailable for native visual capture" }
        val icon = SystemTray.getSystemTray().trayIcons.firstOrNull()
        checkNotNull(icon) { "AWT tray icon was not installed for native visual capture" }
        val listeners = icon.actionListeners.toList()
        check(listeners.isNotEmpty()) { "AWT tray icon has no menu action listener" }
        // Each desktop positions an undecorated popup relative to the pointer with different
        // insets. These fixture anchors preserve the established comparison regions; Windows
        // then moves the popup to its canonical region-capture placement.
        val (anchorX, anchorY) = when {
            sceneId.startsWith("linux-") -> bounds.width / 2 to 400
            sceneId.startsWith("windows-") -> bounds.width / 2 to 400
            sceneId.startsWith("macos-") -> bounds.width / 2 to 530
            else -> error("Unsupported tray visual scene: $sceneId")
        }
        robot.mouseMove(bounds.x + anchorX, bounds.y + anchorY)
        EventQueue.invokeAndWait {
            listeners.forEach { listener ->
                listener.actionPerformed(
                    java.awt.event.ActionEvent(icon, java.awt.event.ActionEvent.ACTION_PERFORMED, "visual-open"),
                )
            }
        }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        var popup: Window? = null
        while (System.nanoTime() < deadline) {
            popup = Window.getWindows().firstOrNull {
                it.name == "vpn-control-tray-menu" && it.isShowing
            }
            if (popup != null) break
            Thread.sleep(100)
        }
        val visiblePopup = checkNotNull(popup) { "VPN Control tray menu did not become visible for capture" }
        activateWindow(visiblePopup)
        return visiblePopup
    }

    /**
     * The isolated Linux fixture places the XEmbed tray at the top-left corner. A real pointer
     * click is required for GtkStatusIcon/Dorkbox to ask the desktop shell to display its menu;
     * there is deliberately no public Dorkbox API that opens that platform-owned popup.
     */
    private fun openNativeTrayMenuWhenAvailable() {
        robot.mouseMove(8, 8)
        robot.mousePress(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
        robot.mouseRelease(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
    }

    private fun captureLinuxSurface(sceneId: String, output: Path, bounds: Rectangle) {
        val command = when (sceneId) {
            // pkexec prompts are session/policy dependent. xmessage is the deterministic native
            // error surface used in the isolated fixture when elevation is unavailable.
            "linux-elevation-error" -> listOf(
                "xmessage", "-center", "-buttons", "OK:0", "-default", "OK", "-title", "VPN Control",
                "Administrator privileges are required to enable VPN mode.\nThe operation was canceled or failed.",
            )
            "linux-update-installer" -> listOf(
                "gdebi-gtk",
                requireVisualPackage(".deb").toString(),
            )
            else -> error("Unsupported Linux native scene: $sceneId")
        }
        captureProcessSurface(command, output, bounds)
    }

    private fun captureMacSurface(sceneId: String, output: Path, bounds: Rectangle) {
        val dmg = requireVisualPackage(".dmg")
        when (sceneId) {
            "macos-dmg" -> {
                val mount = mountDmg(dmg)
                try {
                    captureProcessSurface(listOf("open", mount.toString()), output, bounds, keepProcess = true)
                } finally {
                    runCommand(listOf("hdiutil", "detach", mount.toString(), "-quiet"), wait = true)
                }
            }
            "macos-gatekeeper" -> {
                require(commandOutput(listOf("spctl", "--status")).contains("assessments enabled")) {
                    "Gatekeeper must be enabled in the isolated macOS capture environment"
                }
                val mount = mountDmg(dmg)
                val copiedRoot = Files.createTempDirectory("vpn-control-visual-gatekeeper-")
                try {
                    val mountedApp = Files.list(mount).use { paths ->
                        paths.filter { it.fileName.toString().endsWith(".app") }.findFirst().orElseThrow()
                    }
                    val app = copiedRoot.resolve(mountedApp.fileName.toString())
                    runCommand(listOf("ditto", mountedApp.toString(), app.toString()), true)
                    val quarantineStamp = java.lang.Long.toHexString(System.currentTimeMillis() / 1_000)
                    runCommand(
                        listOf(
                            "xattr", "-r", "-w", "com.apple.quarantine",
                            "0081;$quarantineStamp;VPN Control;", app.toString(),
                        ),
                        true,
                    )
                    captureProcessSurface(listOf("open", app.toString()), output, bounds, keepProcess = true)
                } finally {
                    robot.keyPress(java.awt.event.KeyEvent.VK_ESCAPE)
                    robot.keyRelease(java.awt.event.KeyEvent.VK_ESCAPE)
                    runCommand(listOf("hdiutil", "detach", mount.toString(), "-quiet"), wait = true)
                    copiedRoot.toFile().deleteRecursively()
                }
            }
            "macos-install-confirmation" -> captureProcessSurface(
                listOf(
                    "osascript", "-e",
                    "do shell script \"/usr/bin/true\" with administrator privileges with prompt \"Install VPN Control 2.0.0\"",
                ),
                output,
                bounds,
            )
            else -> error("Unsupported macOS native scene: $sceneId")
        }
    }

    private fun captureProcessSurface(
        command: List<String>,
        output: Path,
        bounds: Rectangle,
        keepProcess: Boolean = false,
    ) {
        val process = runCommand(command, wait = false)
        try {
            Thread.sleep(2_500)
            captureScreen(output, bounds)
        } finally {
            robot.keyPress(java.awt.event.KeyEvent.VK_ESCAPE)
            robot.keyRelease(java.awt.event.KeyEvent.VK_ESCAPE)
            if (!keepProcess && process?.isAlive == true) process.destroy()
        }
    }

    private fun mountDmg(dmg: Path): Path {
        val mount = Files.createTempDirectory("vpn-control-visual-dmg-")
        val process = ProcessBuilder(
            "hdiutil", "attach", dmg.toString(), "-nobrowse", "-readonly", "-mountpoint", mount.toString(), "-quiet",
        ).start()
        check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) {
            "Could not mount visual DMG"
        }
        return mount
    }

    private fun requireVisualPackage(extension: String): Path {
        val path = Path.of(requireNotNull(System.getenv("VPN_CONTROL_VISUAL_PACKAGE")) {
            "VPN_CONTROL_VISUAL_PACKAGE is required for installer scenes"
        })
        require(Files.isRegularFile(path) && path.fileName.toString().endsWith(extension, ignoreCase = true)) {
            "Visual package must be an existing $extension file: $path"
        }
        return path
    }

    private fun runCommand(command: List<String>, wait: Boolean): Process? {
        val process = ProcessBuilder(command)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
        if (!wait) return process
        check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) {
            "Native visual command failed: ${command.joinToString(" ")}"
        }
        return null
    }

    private fun commandOutput(command: List<String>): String {
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) {
            "Native visual command failed: ${command.joinToString(" ")}"
        }
        return output.trim()
    }

    /** Full-screen capture for the Linux and macOS OS-owned scenes. */
    private fun captureScreen(output: Path, bounds: Rectangle) {
        Thread.sleep(800)
        ImageIO.write(robot.createScreenCapture(bounds), "png", output.toFile())
    }

    private fun captureVisibleSurface(output: Path, bounds: Rectangle) {
        if (System.getenv("VPN_CONTROL_VISUAL_EXTERNAL_FRAMEBUFFER") == "1") {
            // Robot needs macOS Screen Recording consent, which a guest cannot safely grant to
            // itself. The agent's loopback VNC client captures this isolated framebuffer instead.
            val ready = output.resolveSibling("${output.fileName}.ready")
            val captured = output.resolveSibling("${output.fileName}.captured")
            Files.writeString(ready, "ready")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)
            while (!Files.exists(captured) && System.nanoTime() < deadline) Thread.sleep(100)
            check(Files.exists(captured)) { "External macOS framebuffer capture did not acknowledge $output" }
            return
        }
        preparePrivateWindowCapturePermission(bounds)
        captureScreen(output, bounds)
    }

    /**
     * macOS 15 can defer its private-window capture consent until a Finder
     * FileDialog is actually visible. Trigger it against the empty fixture,
     * wait for the OS animation, and accept it before preserving evidence.
     */
    private fun preparePrivateWindowCapturePermission(bounds: Rectangle) {
        if (
            macosPrivateWindowPermissionPrepared ||
            !System.getProperty("os.name").startsWith("Mac", ignoreCase = true)
        ) return
        robot.createScreenCapture(bounds)
        Thread.sleep(5_000)
        val allowX = bounds.x + bounds.width / 2
        val allowY = bounds.y + (bounds.height * 0.554).toInt()
        robot.mouseMove(allowX, allowY)
        robot.mousePress(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
        robot.mouseRelease(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
        Thread.sleep(2_000)
        macosPrivateWindowPermissionPrepared = true
    }

    /**
     * The first Robot capture on a fresh macOS runner can raise the system
     * Screen Recording consent sheet. Resolve it before any evidence image is
     * taken so the permission UI cannot contaminate a native scene. The click
     * is scoped to the isolated capture desktop and is harmless when consent
     * was already granted.
     */
    private fun prepareScreenCapturePermission(platform: String) {
        if (platform != "macos" || !System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) return
        val screen = GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration.bounds
        runCatching {
            robot.createScreenCapture(Rectangle(screen.x, screen.y, screen.width, screen.height))
            Thread.sleep(1_200)
            val allowX = screen.x + screen.width / 2
            // At the canonical 1280x800 viewport the consent sheet's primary Allow action is
            // centered at y=443. Keep this proportional so runner chrome offsets cannot move the
            // click onto the explanatory text or leave the permission overlay in every capture.
            val allowY = screen.y + (screen.height * 0.554).toInt()
            robot.mouseMove(allowX, allowY)
            robot.mousePress(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
            robot.mouseRelease(java.awt.event.InputEvent.BUTTON1_DOWN_MASK)
            Thread.sleep(1_200)
        }
    }

    private fun activateWindow(window: Window) {
        onEventThread {
            window.toFront()
            window.requestFocus()
        }
        Thread.sleep(300)
    }

    private fun canonicalCaptureBounds(): Rectangle {
        val screen = GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration.bounds
        require(screen.width >= 1280 && screen.height >= 800) {
            "Native visual desktop must be at least 1280x800; got ${screen.width}x${screen.height}"
        }
        return Rectangle(screen.x, screen.y, 1280, 800)
    }

    private fun waitForVisibleWindow(window: Window) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < deadline) {
            if (window.isShowing) {
                Thread.sleep(1_000)
                return
            }
            Thread.sleep(100)
        }
        error("Application window did not become visible")
    }

    private inline fun <reified T : Window> waitForWindow(): T {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
        while (System.nanoTime() < deadline) {
            Window.getWindows().filterIsInstance<T>().firstOrNull { it.isShowing }?.let {
                Thread.sleep(1_000)
                return it
            }
            Thread.sleep(100)
        }
        error("Native ${T::class.simpleName} did not become visible")
    }

    private fun <T> onEventThread(block: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return block()
        var value: Result<T>? = null
        SwingUtilities.invokeAndWait { value = runCatching(block) }
        return requireNotNull(value).getOrThrow()
    }
}

private fun nativeScenes(manifestPath: Path, platform: String, requested: Set<String>): List<String> {
    val root = Json.parseToJsonElement(Files.readString(manifestPath)).jsonObject
    return root.getValue("scenes").jsonArray
        .map { it.jsonObject }
        .filter { scene -> platform in scene.getValue("platforms").jsonArray.map { it.jsonPrimitive.content } }
        .filter { scene -> scene["geometry_required"]?.jsonPrimitive?.content == "false" }
        .map { scene -> scene.getValue("id").jsonPrimitive.content }
        .filter { sceneId -> requested.isEmpty() || sceneId in requested }
}
