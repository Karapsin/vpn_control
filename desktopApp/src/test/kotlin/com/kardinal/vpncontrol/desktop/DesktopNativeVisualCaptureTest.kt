package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import dorkbox.systemTray.SystemTray as DorkboxSystemTray
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
 */
class DesktopNativeVisualCaptureTest {
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
        val scenes = nativeScenes(manifest, platform, requested)
        require(scenes.isNotEmpty()) { "No native $platform scenes were requested" }
        Files.createDirectories(output)

        val captureBounds = canonicalCaptureBounds()
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
                captureFileDialog(window, save = false, output = output, bounds = bounds)
            }
            sceneId.endsWith("save-dialog") -> withApplicationWindow(sceneId) { window ->
                captureFileDialog(window, save = true, output = output, bounds = bounds)
            }
            "tray" in sceneId || "menu-bar" in sceneId -> captureTray(sceneId, output, bounds)
            platform == "linux" -> captureLinuxSurface(sceneId, output, bounds)
            platform == "windows" -> captureWindowsSurface(sceneId, output, bounds)
            platform == "macos" -> captureMacSurface(sceneId, output, bounds)
            else -> error("Unsupported native visual scene: $platform/$sceneId")
        }
    }

    private fun withApplicationWindow(sceneId: String, block: (ComposeWindow) -> Unit) {
        val testRoot = Files.createTempDirectory("vpn-control-native-visual-")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(testRoot))
        service.replaceStateForVisualCapture(
            visualState(if ("connected" in sceneId) "main-connected" else "main-disconnected"),
            visualLocations(),
            runtimeStatusDetails = listOf("Runtime mode: VPN", "Desktop VPN capability: ready"),
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
        window: ComposeWindow,
        save: Boolean,
        output: Path,
        bounds: Rectangle,
    ) {
        val completed = CountDownLatch(1)
        val thread = Thread({
            try {
                if (save) {
                    DesktopTextTransfer.chooseSaveFile(window, "Export VPN Control diagnostics", "vpn-control-diagnostics.txt")
                } else {
                    DesktopTextTransfer.chooseOpenFile(window, "Import VPN Control configuration")
                }
            } finally {
                completed.countDown()
            }
        }, "vpn-control-native-file-dialog")
        thread.isDaemon = true
        thread.start()
        val dialog = waitForWindow<FileDialog>()
        captureScreen(output, bounds)
        onEventThread {
            dialog.isVisible = false
            dialog.dispose()
        }
        completed.await(10, TimeUnit.SECONDS)
    }

    private fun captureTray(sceneId: String, output: Path, bounds: Rectangle) {
        val connected = "connected" in sceneId && "disconnected" !in sceneId
        val backend = when {
            "tray-awt" in sceneId -> "awt"
            "tray-native" in sceneId -> "native"
            else -> null
        }
        val prior = System.getProperty("vpn.control.linux.trayBackend")
        val priorDorkboxTrayType = DorkboxSystemTray.FORCE_TRAY_TYPE
        if (backend != null) System.setProperty("vpn.control.linux.trayBackend", backend)
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
        try {
            check(available.await(30, TimeUnit.SECONDS)) { "The production tray backend did not become available" }
            if (backend == "native") openNativeTrayMenuWhenAvailable()
            else openAwtTrayMenuWhenAvailable()
            Thread.sleep(1_000)
            captureScreen(output, bounds)
        } finally {
            onEventThread {
                window.isVisible = false
                window.dispose()
            }
            if (prior == null) System.clearProperty("vpn.control.linux.trayBackend")
            else System.setProperty("vpn.control.linux.trayBackend", prior)
            DorkboxSystemTray.FORCE_TRAY_TYPE = priorDorkboxTrayType
        }
    }

    private fun openAwtTrayMenuWhenAvailable() {
        if (!SystemTray.isSupported()) return
        val icon = SystemTray.getSystemTray().trayIcons.firstOrNull() ?: return
        EventQueue.invokeAndWait {
            icon.actionListeners.forEach { listener ->
                listener.actionPerformed(
                    java.awt.event.ActionEvent(icon, java.awt.event.ActionEvent.ACTION_PERFORMED, "visual-open"),
                )
            }
        }
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

    private fun captureWindowsSurface(sceneId: String, output: Path, bounds: Rectangle) {
        val command = when (sceneId) {
            "windows-msi" -> listOf("msiexec.exe", "/i", requireVisualPackage(".msi").toString())
            "windows-update-installer" -> listOf(
                "msiexec.exe", "/i", requireVisualPackage(".msi").toString(), "/passive", "/norestart",
            )
            "windows-uac" -> listOf(
                "powershell.exe", "-NoProfile", "-Command",
                "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-Command','Start-Sleep 30'",
            )
            else -> error("Unsupported Windows native scene: $sceneId")
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

    private fun captureScreen(output: Path, bounds: Rectangle) {
        Thread.sleep(800)
        ImageIO.write(robot.createScreenCapture(bounds), "png", output.toFile())
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
