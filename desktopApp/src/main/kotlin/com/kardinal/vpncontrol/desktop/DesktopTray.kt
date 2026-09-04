package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import dorkbox.systemTray.MenuItem as DorkboxMenuItem
import dorkbox.systemTray.Separator as DorkboxSeparator
import dorkbox.systemTray.SystemTray as DorkboxSystemTray
import java.awt.BasicStroke
import java.awt.Color as AwtColor
import java.awt.Cursor
import java.awt.Dimension
import java.awt.GradientPaint
import java.awt.GraphicsEnvironment
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Image
import java.awt.MouseInfo
import java.awt.Point
import java.awt.Polygon
import java.awt.RenderingHints
import java.awt.TrayIcon
import java.awt.Window
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.image.BufferedImage
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import javax.imageio.ImageIO
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSeparator
import javax.swing.JWindow
import javax.swing.SwingUtilities
import javax.swing.Timer
import kotlin.concurrent.thread
import kotlin.math.roundToInt
import java.awt.SystemTray as AwtSystemTray

private const val DefaultTrayAppName = "VPN Control"
private const val DefaultLinuxTrayIconSize = 24
private const val TinyLinuxTrayIconSize = 12
private const val MinimumLinuxTrayArtworkSize = 10
private const val LinuxTrayArtworkInsetRatio = 0.12
private const val LinuxAwtXEmbedPaintGuardPixels = 4
private const val MinimumNonLinuxTrayIconSize = 22
private const val MaximumTrayIconSize = 128
private const val TrayInstallRetryDelayMillis = 1_000
private const val TrayInstallMaxAttempts = 60
private const val LinuxAwtTrayVisibilityCheckDelayMillis = 500
private const val LinuxAwtTrayVisibilityMaxMisses = 6

@Composable
internal fun DesktopTrayIcon(
    appTitle: String,
    connectionActionLabel: String,
    findBestLabel: String,
    showWindowLabel: String,
    hideWindowLabel: String,
    exitLabel: String,
    connectionActionEnabled: Boolean,
    findBestEnabled: Boolean,
    onToggleConnection: () -> Unit,
    onFindBest: () -> Unit,
    onShowWindow: () -> Unit,
    onHideWindow: () -> Unit,
    onExit: () -> Unit,
    onTrayAvailable: () -> Unit = {},
    onTrayUnavailable: () -> Unit = {},
) {
    val currentAppTitle = rememberUpdatedState(appTitle)
    val currentMenuState = rememberUpdatedState(
        TrayMenuState(
            connectionActionLabel = connectionActionLabel,
            findBestLabel = findBestLabel,
            showWindowLabel = showWindowLabel,
            hideWindowLabel = hideWindowLabel,
            exitLabel = exitLabel,
            connectionActionEnabled = connectionActionEnabled,
            findBestEnabled = findBestEnabled,
            onToggleConnection = onToggleConnection,
            onFindBest = onFindBest,
            onShowWindow = onShowWindow,
            onHideWindow = onHideWindow,
            onExit = onExit,
        ),
    )
    val trayHandleHolder = remember { DesktopTrayHandleHolder() }

    SideEffect {
        trayHandleHolder.update(appTitle, currentMenuState.value)
    }

    DisposableEffect(Unit) {
        val disposed = AtomicBoolean(false)
        AsyncDesktopTrayBackendInstaller(createDesktopTrayBackendInstaller()).install(
            appTitle = { currentAppTitle.value },
            menuState = { currentMenuState.value },
            onAvailable = {
                SwingUtilities.invokeLater {
                    if (!disposed.get()) onTrayAvailable()
                }
            },
            onUnavailable = {
                SwingUtilities.invokeLater {
                    if (!disposed.get()) onTrayUnavailable()
                }
            },
        ) { trayHandle ->
            val accepted = trayHandleHolder.install(trayHandle)
            if (accepted && trayHandle == null) {
                SwingUtilities.invokeLater {
                    if (!disposed.get()) onTrayUnavailable()
                }
            }
        }
        onDispose {
            disposed.set(true)
            trayHandleHolder.dispose()
        }
    }
}

internal fun isDesktopTraySupported(): Boolean {
    val isHeadless = runCatching { GraphicsEnvironment.isHeadless() }.getOrDefault(true)
    if (isHeadless) return false
    return when (desktopTrayPlatform()) {
        DesktopTrayPlatform.Linux -> true
        DesktopTrayPlatform.Windows,
        DesktopTrayPlatform.MacOs,
        DesktopTrayPlatform.Other,
        -> isAwtDesktopTraySupported()
    }
}

internal enum class DesktopTrayBackendKind {
    NativeLinux,
    Awt,
}

internal enum class LinuxTrayBackendPreference {
    NativeFirst,
    AwtFirst,
}

internal enum class DesktopTrayPlatform {
    Linux,
    Windows,
    MacOs,
    Other,
}

internal fun desktopTrayPlatform(osName: String = System.getProperty("os.name")): DesktopTrayPlatform {
    val normalized = osName.lowercase()
    return when {
        "linux" in normalized -> DesktopTrayPlatform.Linux
        "windows" in normalized -> DesktopTrayPlatform.Windows
        "mac" in normalized || "darwin" in normalized -> DesktopTrayPlatform.MacOs
        else -> DesktopTrayPlatform.Other
    }
}

internal fun selectDesktopTrayBackendKinds(
    osName: String = System.getProperty("os.name"),
    isHeadless: Boolean = runCatching { GraphicsEnvironment.isHeadless() }.getOrDefault(true),
    awtSupported: Boolean = isAwtDesktopTraySupported(),
    linuxPreference: LinuxTrayBackendPreference = LinuxTrayBackendPreference.NativeFirst,
): List<DesktopTrayBackendKind> {
    if (isHeadless) return emptyList()
    return when (desktopTrayPlatform(osName)) {
        DesktopTrayPlatform.Linux -> when (linuxPreference) {
            LinuxTrayBackendPreference.NativeFirst -> listOf(
                DesktopTrayBackendKind.NativeLinux,
                DesktopTrayBackendKind.Awt,
            )
            LinuxTrayBackendPreference.AwtFirst -> listOf(
                DesktopTrayBackendKind.Awt,
                DesktopTrayBackendKind.NativeLinux,
            )
        }
        DesktopTrayPlatform.Windows,
        DesktopTrayPlatform.MacOs,
        DesktopTrayPlatform.Other,
        -> if (awtSupported) listOf(DesktopTrayBackendKind.Awt) else emptyList()
    }
}

internal interface DesktopTrayHandle {
    fun update(appTitle: String, menuState: TrayMenuState)

    fun dispose()
}

internal interface DesktopTrayBackend {
    fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit,
        onUnavailable: () -> Unit,
    ): DesktopTrayHandle?
}

internal class DesktopTrayBackendInstaller(
    private val backends: List<DesktopTrayBackend>,
) {
    fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit = {},
        onUnavailable: () -> Unit = {},
    ): DesktopTrayHandle? {
        for (backend in backends) {
            val handle = runCatching {
                backend.install(
                    appTitle = appTitle,
                    menuState = menuState,
                    onAvailable = onAvailable,
                    onUnavailable = onUnavailable,
                )
            }.getOrNull()
            if (handle != null) return handle
        }
        return null
    }
}

internal class AsyncDesktopTrayBackendInstaller(
    private val installer: DesktopTrayBackendInstaller,
    private val launchWorker: ((() -> Unit) -> Unit) = { task ->
        thread(
            start = true,
            isDaemon = true,
            name = "vpn-control-tray-install",
            block = task,
        )
    },
) {
    fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit,
        onUnavailable: () -> Unit,
        onComplete: (DesktopTrayHandle?) -> Unit,
    ) {
        launchWorker {
            onComplete(
                installer.install(
                    appTitle = appTitle,
                    menuState = menuState,
                    onAvailable = onAvailable,
                    onUnavailable = onUnavailable,
                ),
            )
        }
    }
}

private fun createDesktopTrayBackendInstaller(): DesktopTrayBackendInstaller {
    val backends = selectDesktopTrayBackendKinds(
        linuxPreference = detectLinuxTrayBackendPreference(),
    )
        .map { kind ->
            when (kind) {
                DesktopTrayBackendKind.NativeLinux -> NativeLinuxTrayBackend()
                DesktopTrayBackendKind.Awt -> AwtTrayBackend()
            }
        }
    return DesktopTrayBackendInstaller(backends)
}

private fun isAwtDesktopTraySupported(): Boolean {
    return runCatching {
        !GraphicsEnvironment.isHeadless() && AwtSystemTray.isSupported()
    }.getOrDefault(false)
}

internal fun detectLinuxTrayBackendPreference(
    env: Map<String, String> = System.getenv(),
    property: (String) -> String? = { System.getProperty(it) },
    processCommands: () -> Sequence<String> = { currentUserProcessCommands() },
): LinuxTrayBackendPreference {
    explicitLinuxTrayBackend(property, env)?.let { return it }
    if (isXEmbedFirstDesktopSession(env)) return LinuxTrayBackendPreference.AwtFirst
    if (isPolybarRunning(processCommands)) return LinuxTrayBackendPreference.AwtFirst
    return LinuxTrayBackendPreference.NativeFirst
}

private fun explicitLinuxTrayBackend(
    property: (String) -> String?,
    env: Map<String, String>,
): LinuxTrayBackendPreference? {
    val explicit = listOfNotNull(
        property("vpn.control.linux.trayBackend"),
        env["VPN_CONTROL_LINUX_TRAY_BACKEND"],
    )
        .firstOrNull { it.isNotBlank() }
        ?.trim()
        ?.lowercase()

    return when (explicit) {
        "awt", "xembed" -> LinuxTrayBackendPreference.AwtFirst
        "native", "dorkbox" -> LinuxTrayBackendPreference.NativeFirst
        else -> null
    }
}

private fun isXEmbedFirstDesktopSession(env: Map<String, String>): Boolean {
    val sessionText = listOf(
        env["XDG_CURRENT_DESKTOP"],
        env["DESKTOP_SESSION"],
        env["GDMSESSION"],
    )
        .filterNotNull()
        .joinToString(separator = " ")
        .lowercase()
    if (sessionText.isBlank()) return false

    val sessionTokens = sessionText.split(':', ';', ',', ' ', '-')
    return XEmbedFirstDesktopTokens.any { token ->
        sessionTokens.any { it == token }
    }
}

private val XEmbedFirstDesktopTokens = setOf(
    "i3",
    "bspwm",
    "awesome",
    "xmonad",
    "herbstluftwm",
    "qtile",
    "openbox",
    "fluxbox",
    "icewm",
    "dwm",
)

private fun isPolybarRunning(processCommands: () -> Sequence<String>): Boolean {
    return runCatching {
        processCommands().any { command ->
            val normalized = command.lowercase()
            normalized == "polybar" ||
                normalized.endsWith("/polybar") ||
                normalized.endsWith(" polybar") ||
                "/polybar " in normalized
        }
    }.getOrDefault(false)
}

private fun currentUserProcessCommands(): Sequence<String> {
    return runCatching {
        ProcessHandle.allProcesses()
            .iterator()
            .asSequence()
            .mapNotNull { process ->
                process.info().command().orElse(null)
                    ?: process.info().commandLine().orElse(null)
            }
    }.getOrDefault(emptySequence())
}

private class DesktopTrayHandleHolder {
    private var handle: DesktopTrayHandle? = null
    private var latestAppTitle: String? = null
    private var latestMenuState: TrayMenuState? = null
    private var disposed = false

    @Synchronized
    fun update(appTitle: String, menuState: TrayMenuState) {
        latestAppTitle = appTitle
        latestMenuState = menuState
        handle?.update(appTitle, menuState)
    }

    @Synchronized
    fun install(candidate: DesktopTrayHandle?): Boolean {
        if (disposed) {
            candidate?.dispose()
            return false
        }
        handle = candidate
        val appTitle = latestAppTitle
        val menuState = latestMenuState
        if (candidate != null && appTitle != null && menuState != null) {
            candidate.update(appTitle, menuState)
        }
        return true
    }

    @Synchronized
    fun dispose() {
        if (disposed) return
        disposed = true
        handle?.dispose()
        handle = null
    }
}

private class AwtTrayBackend : DesktopTrayBackend {
    override fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit,
        onUnavailable: () -> Unit,
    ): DesktopTrayHandle? {
        if (!isAwtDesktopTraySupported()) return null
        val handle = AwtTrayHandle(
            popup = TrayPopupController(),
            onAvailable = onAvailable,
            onUnavailable = onUnavailable,
        )
        val trayRegistration = RetryingTrayRegistration(
            target = AwtTrayRegistrationTarget(
                appTitle = appTitle,
                popup = handle.popup,
                menuState = menuState,
            ),
            scheduler = SwingTrayRetryScheduler,
            onInstalled = { icon ->
                handle.installTrayIcon(icon)
                handle.update(appTitle(), menuState())
            },
            onUnavailable = handle::markUnavailable,
        )
        handle.registration = trayRegistration
        trayRegistration.start()
        return handle
    }
}

private class AwtTrayHandle(
    val popup: TrayPopupController,
    private val onAvailable: () -> Unit,
    private val onUnavailable: () -> Unit,
) : DesktopTrayHandle {
    var registration: RetryingTrayRegistration<TrayIcon>? = null
    private var trayIcon: TrayIcon? = null
    private var linuxTrayMonitorTimer: Timer? = null
    private var disposed = false
    private var available = false
    private var missingVisibilityChecks = 0

    override fun update(appTitle: String, menuState: TrayMenuState) {
        if (disposed) return
        val icon = trayIcon ?: return
        if (icon.toolTip != appTitle) {
            icon.toolTip = appTitle
        }
    }

    fun installTrayIcon(icon: TrayIcon) {
        if (disposed) return
        trayIcon = icon
        if (desktopTrayPlatform() != DesktopTrayPlatform.Linux) {
            markAvailable()
            return
        }
        startLinuxTrayMonitor()
        checkLinuxTrayVisibility()
    }

    fun markUnavailable() {
        if (disposed) return
        dispose()
        onUnavailable()
    }

    private fun markAvailable() {
        if (disposed || available) return
        available = true
        onAvailable()
    }

    private fun startLinuxTrayMonitor() {
        if (linuxTrayMonitorTimer != null) return
        linuxTrayMonitorTimer = Timer(LinuxAwtTrayVisibilityCheckDelayMillis) {
            checkLinuxTrayVisibility()
        }.apply {
            isRepeats = true
            initialDelay = LinuxAwtTrayVisibilityCheckDelayMillis
            start()
        }
    }

    private fun checkLinuxTrayVisibility() {
        if (disposed) return
        val icon = trayIcon ?: return
        if (!isAwtTrayIconRegistered(icon)) {
            markUnavailable()
            return
        }

        val frameSize = currentLinuxAwtTrayFrameSize()
        if (frameSize == null) {
            missingVisibilityChecks += 1
            if (missingVisibilityChecks >= LinuxAwtTrayVisibilityMaxMisses) {
                markUnavailable()
            }
            return
        }

        missingVisibilityChecks = 0
        markAvailable()
        refreshLinuxAwtTrayImage(icon, frameSize)
    }

    private fun refreshLinuxAwtTrayImage(icon: TrayIcon, frameSize: Int) {
        val currentImageSize = icon.image?.getWidth(null) ?: -1
        if (currentImageSize != frameSize) {
            icon.image = createTrayImage(
                DesktopTrayImageConfig(
                    imageSize = frameSize,
                    autoSize = false,
                    preferFixedResource = true,
                ),
            )
        }
    }

    override fun dispose() {
        if (disposed) return
        disposed = true
        popup.dismiss()
        linuxTrayMonitorTimer?.stop()
        linuxTrayMonitorTimer = null
        registration?.dispose()
        registration = null
        trayIcon = null
    }
}

internal fun interface NativeLinuxTrayGateway {
    fun get(appName: String): NativeLinuxTrayPeer?
}

internal interface NativeLinuxTrayPeer {
    fun setImage(imageUrl: URL)

    fun setTooltip(text: String)

    fun addMenuItem(
        text: String,
        enabled: Boolean,
        action: () -> Unit,
    ): NativeLinuxTrayMenuItem

    fun addSeparator()

    fun shutdown()
}

internal interface NativeLinuxTrayMenuItem {
    fun setText(text: String)

    fun setEnabled(enabled: Boolean)
}

internal fun interface NativeTrayIconResolver {
    fun resolve(): URL?
}

internal fun interface TrayActionDispatcher {
    fun dispatch(action: () -> Unit)
}

private object SwingTrayActionDispatcher : TrayActionDispatcher {
    override fun dispatch(action: () -> Unit) {
        SwingUtilities.invokeLater(action)
    }
}

internal class NativeLinuxTrayBackend(
    private val gateway: NativeLinuxTrayGateway = DorkboxNativeLinuxTrayGateway,
    private val iconResolver: NativeTrayIconResolver = NativeTrayIconResolver { resolveNativeTrayIconUrl() },
    private val dispatcher: TrayActionDispatcher = SwingTrayActionDispatcher,
    private val isHeadless: () -> Boolean = { GraphicsEnvironment.isHeadless() },
) : DesktopTrayBackend {
    override fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit,
        onUnavailable: () -> Unit,
    ): DesktopTrayHandle? {
        if (runCatching { isHeadless() }.getOrDefault(true)) return null
        val tray = gateway.get(DefaultTrayAppName) ?: return null
        val imageUrl = iconResolver.resolve() ?: run {
            runCatching { tray.shutdown() }
            return null
        }
        return runCatching {
            val handle = NativeLinuxTrayHandle(
                tray = tray,
                initialAppTitle = appTitle(),
                initialMenuState = menuState(),
                dispatcher = dispatcher,
            )
            tray.setImage(imageUrl)
            onAvailable()
            handle
        }.getOrElse {
            runCatching { tray.shutdown() }
            null
        }
    }
}

private class NativeLinuxTrayHandle(
    private val tray: NativeLinuxTrayPeer,
    initialAppTitle: String,
    initialMenuState: TrayMenuState,
    private val dispatcher: TrayActionDispatcher,
) : DesktopTrayHandle {
    private var disposed = false
    private var currentState = initialMenuState
    private val showWindowItem: NativeLinuxTrayMenuItem
    private val hideWindowItem: NativeLinuxTrayMenuItem
    private val connectionItem: NativeLinuxTrayMenuItem
    private val findBestItem: NativeLinuxTrayMenuItem
    private val exitItem: NativeLinuxTrayMenuItem

    init {
        tray.setTooltip(initialAppTitle)
        showWindowItem = tray.addMenuItem(initialMenuState.showWindowLabel, enabled = true) {
            dispatchCurrent { it.onShowWindow }
        }
        hideWindowItem = tray.addMenuItem(initialMenuState.hideWindowLabel, enabled = true) {
            dispatchCurrent { it.onHideWindow }
        }
        tray.addSeparator()
        connectionItem = tray.addMenuItem(
            text = initialMenuState.connectionActionLabel,
            enabled = initialMenuState.connectionActionEnabled,
        ) {
            dispatchCurrentIfEnabled(
                enabled = { it.connectionActionEnabled },
                action = { it.onToggleConnection },
            )
        }
        findBestItem = tray.addMenuItem(
            text = initialMenuState.findBestLabel,
            enabled = initialMenuState.findBestEnabled,
        ) {
            dispatchCurrentIfEnabled(
                enabled = { it.findBestEnabled },
                action = { it.onFindBest },
            )
        }
        tray.addSeparator()
        exitItem = tray.addMenuItem(initialMenuState.exitLabel, enabled = true) {
            exitFromTray()
        }
    }

    override fun update(appTitle: String, menuState: TrayMenuState) {
        if (disposed) return
        currentState = menuState
        tray.setTooltip(appTitle)
        showWindowItem.setText(menuState.showWindowLabel)
        showWindowItem.setEnabled(true)
        hideWindowItem.setText(menuState.hideWindowLabel)
        hideWindowItem.setEnabled(true)
        connectionItem.setText(menuState.connectionActionLabel)
        connectionItem.setEnabled(menuState.connectionActionEnabled)
        findBestItem.setText(menuState.findBestLabel)
        findBestItem.setEnabled(menuState.findBestEnabled)
        exitItem.setText(menuState.exitLabel)
        exitItem.setEnabled(true)
    }

    override fun dispose() {
        if (disposed) return
        disposed = true
        runCatching { tray.shutdown() }
    }

    private fun dispatchCurrent(action: (TrayMenuState) -> (() -> Unit)) {
        if (disposed) return
        val callback = action(currentState)
        dispatcher.dispatch(callback)
    }

    private fun dispatchCurrentIfEnabled(
        enabled: (TrayMenuState) -> Boolean,
        action: (TrayMenuState) -> (() -> Unit),
    ) {
        if (!enabled(currentState)) return
        dispatchCurrent(action)
    }

    private fun exitFromTray() {
        if (disposed) return
        val exit = currentState.onExit
        dispose()
        dispatcher.dispatch(exit)
    }
}

private object DorkboxNativeLinuxTrayGateway : NativeLinuxTrayGateway {
    override fun get(appName: String): NativeLinuxTrayPeer? {
        configureDorkboxAppName(appName)
        return runCatching { DorkboxSystemTray.get(appName) }
            .getOrNull()
            ?.let(::DorkboxNativeLinuxTrayPeer)
    }
}

private class DorkboxNativeLinuxTrayPeer(
    private val tray: DorkboxSystemTray,
) : NativeLinuxTrayPeer {
    override fun setImage(imageUrl: URL) {
        tray.setImage(imageUrl)
    }

    override fun setTooltip(text: String) {
        runCatching { tray.setTooltip(text.take(64)) }
    }

    override fun addMenuItem(
        text: String,
        enabled: Boolean,
        action: () -> Unit,
    ): NativeLinuxTrayMenuItem {
        val menuItem = DorkboxMenuItem(text) {
            action()
        }
        menuItem.setEnabled(enabled)
        tray.menu.add(menuItem)
        return DorkboxNativeLinuxTrayMenuItem(menuItem)
    }

    override fun addSeparator() {
        tray.menu.add(DorkboxSeparator())
    }

    override fun shutdown() {
        tray.shutdown()
    }
}

private class DorkboxNativeLinuxTrayMenuItem(
    private val menuItem: DorkboxMenuItem,
) : NativeLinuxTrayMenuItem {
    override fun setText(text: String) {
        menuItem.setText(text)
    }

    override fun setEnabled(enabled: Boolean) {
        menuItem.setEnabled(enabled)
    }
}

private fun configureDorkboxAppName(appName: String) {
    runCatching {
        DorkboxSystemTray::class.java.getField("APP_NAME").set(null, appName)
    }
}

private class AwtTrayRegistrationTarget(
    private val appTitle: () -> String,
    private val popup: TrayPopupController,
    private val menuState: () -> TrayMenuState,
) : TrayRegistrationTarget<TrayIcon> {
    private fun createIcon(trayIconSize: Dimension): TrayIcon {
        return createTrayIcon(
            appTitle = appTitle(),
            trayIconSize = trayIconSize,
            popup = popup,
            menuState = menuState,
        )
    }

    override fun install(): TrayInstallResult<TrayIcon> {
        if (!isAwtDesktopTraySupported()) return TrayInstallResult.Unsupported
        val tray = runCatching { AwtSystemTray.getSystemTray() }
            .getOrElse { return TrayInstallResult.RetryableFailure }
        val trayIcon = runCatching { createIcon(tray.trayIconSize) }
            .getOrElse { return TrayInstallResult.RetryableFailure }
        return runCatching {
            tray.add(trayIcon)
            if (tray.trayIcons.any { it === trayIcon }) {
                TrayInstallResult.Installed(trayIcon)
            } else {
                runCatching { tray.remove(trayIcon) }
                TrayInstallResult.RetryableFailure
            }
        }.getOrElse {
            runCatching { tray.remove(trayIcon) }
            TrayInstallResult.RetryableFailure
        }
    }

    override fun remove(icon: TrayIcon) {
        runCatching { AwtSystemTray.getSystemTray().remove(icon) }
    }
}

private fun createTrayIcon(
    appTitle: String,
    trayIconSize: Dimension,
    popup: TrayPopupController,
    menuState: () -> TrayMenuState,
): TrayIcon {
    fun toggleMenu() {
        val anchor = MouseInfo.getPointerInfo()?.location ?: Point(0, 0)
        val state = menuState()
        popup.toggle(
            anchor = anchor,
            connectionActionLabel = state.connectionActionLabel,
            findBestLabel = state.findBestLabel,
            showWindowLabel = state.showWindowLabel,
            hideWindowLabel = state.hideWindowLabel,
            exitLabel = state.exitLabel,
            connectionActionEnabled = state.connectionActionEnabled,
            findBestEnabled = state.findBestEnabled,
            onToggleConnection = state.onToggleConnection,
            onFindBest = state.onFindBest,
            onShowWindow = state.onShowWindow,
            onHideWindow = state.onHideWindow,
            onExit = state.onExit,
        )
    }

    val imageConfig = desktopTrayImageConfig(trayIconSize)
    val trayIcon = TrayIcon(createTrayImage(imageConfig), appTitle).apply {
        isImageAutoSize = imageConfig.autoSize
        addActionListener { toggleMenu() }
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(event: MouseEvent) {
                    if (event.button == MouseEvent.BUTTON1) {
                        toggleMenu()
                    }
                }

                override fun mouseReleased(event: MouseEvent) {
                    if (event.isPopupTrigger || event.button == MouseEvent.BUTTON3) {
                        toggleMenu()
                    }
                }
            },
        )
    }
    return trayIcon
}

internal sealed class TrayInstallResult<out T> {
    data class Installed<T>(val icon: T) : TrayInstallResult<T>()
    object RetryableFailure : TrayInstallResult<Nothing>()
    object Unsupported : TrayInstallResult<Nothing>()
}

internal interface TrayRegistrationTarget<T> {
    fun install(): TrayInstallResult<T>

    fun remove(icon: T)
}

internal fun interface TrayRetryScheduler {
    fun schedule(delayMillis: Int, action: () -> Unit): TrayRetryHandle
}

internal fun interface TrayRetryHandle {
    fun cancel()
}

internal data class TrayRegistrationRetryPolicy(
    val maxAttempts: Int = TrayInstallMaxAttempts,
    val retryDelayMillis: Int = TrayInstallRetryDelayMillis,
) {
    init {
        require(maxAttempts >= 1) { "maxAttempts must be at least 1" }
        require(retryDelayMillis >= 0) { "retryDelayMillis must be non-negative" }
    }
}

internal class RetryingTrayRegistration<T>(
    private val target: TrayRegistrationTarget<T>,
    private val scheduler: TrayRetryScheduler,
    private val retryPolicy: TrayRegistrationRetryPolicy = TrayRegistrationRetryPolicy(),
    private val onInstalled: (T) -> Unit = {},
    private val onUnavailable: () -> Unit = {},
) {
    private var attempts = 0
    private var disposed = false
    private var unavailableReported = false
    private var pendingRetry: TrayRetryHandle? = null

    var installedIcon: T? = null
        private set

    fun start() {
        if (attempts > 0 || disposed || installedIcon != null) return
        attemptInstall()
    }

    fun dispose() {
        disposed = true
        pendingRetry?.cancel()
        pendingRetry = null
        installedIcon?.let { icon ->
            runCatching { target.remove(icon) }
        }
        installedIcon = null
    }

    private fun attemptInstall() {
        if (disposed || installedIcon != null) return
        pendingRetry?.cancel()
        pendingRetry = null
        attempts += 1
        when (val result = runCatching { target.install() }.getOrDefault(TrayInstallResult.RetryableFailure)) {
            is TrayInstallResult.Installed -> {
                installedIcon = result.icon
                unavailableReported = false
                runCatching { onInstalled(result.icon) }
            }
            TrayInstallResult.RetryableFailure -> handleRetryableFailure()
            TrayInstallResult.Unsupported -> reportUnavailable()
        }
    }

    private fun handleRetryableFailure() {
        if (disposed) return
        if (attempts >= retryPolicy.maxAttempts) {
            reportUnavailable()
            return
        }
        pendingRetry = scheduler.schedule(retryPolicy.retryDelayMillis) {
            attemptInstall()
        }
    }

    private fun reportUnavailable() {
        if (disposed || unavailableReported || installedIcon != null) return
        unavailableReported = true
        runCatching { onUnavailable() }
    }
}

private object SwingTrayRetryScheduler : TrayRetryScheduler {
    override fun schedule(delayMillis: Int, action: () -> Unit): TrayRetryHandle {
        val timer = Timer(delayMillis) { action() }.apply {
            isRepeats = false
            start()
        }
        return TrayRetryHandle { timer.stop() }
    }
}

internal data class DesktopTrayImageConfig(
    val imageSize: Int,
    val autoSize: Boolean,
    val preferFixedResource: Boolean,
)

internal fun desktopTrayImageConfig(
    trayIconSize: Dimension,
    osName: String = System.getProperty("os.name"),
): DesktopTrayImageConfig {
    val isLinux = osName.lowercase().contains("linux")
    if (isLinux) {
        return DesktopTrayImageConfig(
            imageSize = linuxTrayIconSize(trayIconSize),
            autoSize = false,
            preferFixedResource = true,
        )
    }
    return DesktopTrayImageConfig(
        imageSize = maxOf(trayIconSize.width, trayIconSize.height, MinimumNonLinuxTrayIconSize)
            .coerceAtMost(MaximumTrayIconSize),
        autoSize = true,
        preferFixedResource = false,
    )
}

private fun linuxTrayIconSize(trayIconSize: Dimension): Int {
    val positiveDimensions = listOf(trayIconSize.width, trayIconSize.height)
        .filter { it > 0 }
    val hostSize = positiveDimensions.maxOrNull() ?: DefaultLinuxTrayIconSize
    return (hostSize.coerceAtMost(MaximumTrayIconSize) + LinuxAwtXEmbedPaintGuardPixels)
        .coerceAtMost(MaximumTrayIconSize)
}

private fun currentLinuxAwtTrayFrameSize(): Int? {
    return Window.getWindows()
        .asSequence()
        .filter { window ->
            window.isShowing &&
                window.javaClass.name.contains("TrayIconEmbeddedFrame") &&
                window.width > 0 &&
                window.height > 0
        }
        .map { window -> maxOf(window.width, window.height).coerceAtMost(MaximumTrayIconSize) }
        .firstOrNull()
}

private fun isAwtTrayIconRegistered(icon: TrayIcon): Boolean {
    return runCatching {
        AwtSystemTray.getSystemTray().trayIcons.any { it === icon }
    }.getOrDefault(false)
}

internal data class TrayMenuState(
    val connectionActionLabel: String,
    val findBestLabel: String,
    val showWindowLabel: String,
    val hideWindowLabel: String,
    val exitLabel: String,
    val connectionActionEnabled: Boolean,
    val findBestEnabled: Boolean,
    val onToggleConnection: () -> Unit,
    val onFindBest: () -> Unit,
    val onShowWindow: () -> Unit,
    val onHideWindow: () -> Unit,
    val onExit: () -> Unit,
)

private fun createTrayImage(config: DesktopTrayImageConfig): Image {
    if (config.preferFixedResource) {
        loadDesktopIconImage(listOf("tray_icon_linux.png"))
            ?.let { return renderLinuxTrayImage(it, config.imageSize) }
    }
    loadDesktopIconImage(listOf("tray_icon.png", "gen_icon.png"))
        ?.let { return scaleDesktopIconForTray(it, config.imageSize) }
    return createFallbackTrayImage(config.imageSize)
}

private fun resolveNativeTrayIconUrl(): URL? {
    return loadDesktopIconUrl(listOf("tray_icon_linux.png", "tray_icon.png", "gen_icon.png"))
}

private fun loadDesktopIconUrl(resources: List<String>): URL? {
    val classLoader = Thread.currentThread().contextClassLoader ?: ClassLoader.getSystemClassLoader()
    return resources.firstNotNullOfOrNull(classLoader::getResource)
}

private fun loadDesktopIconImage(resources: List<String>): BufferedImage? {
    val classLoader = Thread.currentThread().contextClassLoader ?: ClassLoader.getSystemClassLoader()
    return resources
        .firstNotNullOfOrNull { resource ->
            runCatching {
                classLoader.getResourceAsStream(resource)?.use(ImageIO::read)
            }.getOrNull()
        }
}

internal fun renderLinuxTrayImage(source: BufferedImage, size: Int): BufferedImage {
    require(size >= 1) { "size must be at least 1" }
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
    val graphics = image.createGraphics()
    graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
    graphics.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
    val background = averageCornerRgb(source)
    graphics.color = AwtColor(background)
    graphics.fillRect(0, 0, size, size)

    if (size < TinyLinuxTrayIconSize) {
        paintTinyLinuxTrayGlyph(graphics, size)
    } else {
        val inset = linuxTrayArtworkInset(size)
        val drawSize = (size - inset * 2).coerceAtLeast(1)
        graphics.drawImage(
            source,
            inset,
            inset,
            inset + drawSize,
            inset + drawSize,
            0,
            0,
            source.width,
            source.height,
            null,
        )
    }

    graphics.dispose()
    return image
}

private fun linuxTrayArtworkInset(size: Int): Int {
    val preferredInset = maxOf(1, (size * LinuxTrayArtworkInsetRatio).roundToInt())
    val maxInset = ((size - MinimumLinuxTrayArtworkSize) / 2).coerceAtLeast(0)
    return preferredInset.coerceAtMost(maxInset)
}

private fun paintTinyLinuxTrayGlyph(graphics: Graphics2D, size: Int) {
    if (size < 4) return
    graphics.scale(size / 16.0, size / 16.0)

    val shield = Polygon(
        intArrayOf(8, 12, 12, 10, 8, 6, 4, 4),
        intArrayOf(2, 4, 8, 12, 14, 12, 8, 4),
        8,
    )
    graphics.paint = GradientPaint(
        4f,
        2f,
        AwtColor(255, 255, 255),
        12f,
        14f,
        AwtColor(196, 222, 250),
    )
    graphics.fillPolygon(shield)

    graphics.color = AwtColor(0, 70, 188)
    graphics.stroke = BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
    graphics.drawLine(5, 8, 7, 10)
    graphics.drawLine(7, 10, 11, 5)
}

private fun scaleDesktopIconForTray(source: BufferedImage, size: Int): Image {
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
    val graphics = image.createGraphics()
    graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
    graphics.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
    val background = averageCornerRgb(source)
    graphics.color = AwtColor(background)
    graphics.fillRect(0, 0, size, size)
    val bounds = findIconContentBounds(source, background)
    val visualBounds = findBrightContentBounds(source) ?: bounds
    val maxDrawSize = (size * 0.82).coerceAtLeast(1.0)
    val scale = maxDrawSize / maxOf(bounds.width, bounds.height)
    val drawWidth = (bounds.width * scale).roundToInt().coerceIn(1, size)
    val drawHeight = (bounds.height * scale).roundToInt().coerceIn(1, size)
    val offsetX = (size / 2.0 - (visualBounds.centerX - bounds.x) * scale)
        .roundToInt()
        .coerceIn(0, size - drawWidth)
    val offsetY = (size / 2.0 - (visualBounds.centerY - bounds.y) * scale)
        .roundToInt()
        .coerceIn(0, size - drawHeight)
    graphics.drawImage(
        source,
        offsetX,
        offsetY,
        offsetX + drawWidth,
        offsetY + drawHeight,
        bounds.x,
        bounds.y,
        bounds.x + bounds.width,
        bounds.y + bounds.height,
        null,
    )
    graphics.dispose()
    return image
}

private data class IconContentBounds(
    val x: Int,
    val y: Int,
    val width: Int,
    val height: Int,
) {
    val centerX: Double
        get() = x + (width - 1) / 2.0
    val centerY: Double
        get() = y + (height - 1) / 2.0
}

private fun findIconContentBounds(source: BufferedImage, background: Int): IconContentBounds {
    var minX = source.width
    var minY = source.height
    var maxX = -1
    var maxY = -1
    for (y in 0 until source.height) {
        for (x in 0 until source.width) {
            if (!isCloseToBackground(source.getRGB(x, y), background)) {
                if (x < minX) minX = x
                if (y < minY) minY = y
                if (x > maxX) maxX = x
                if (y > maxY) maxY = y
            }
        }
    }
    if (maxX < minX || maxY < minY) {
        return IconContentBounds(0, 0, source.width, source.height)
    }
    val padding = maxOf(source.width, source.height) / 64
    minX = (minX - padding).coerceAtLeast(0)
    minY = (minY - padding).coerceAtLeast(0)
    maxX = (maxX + padding).coerceAtMost(source.width - 1)
    maxY = (maxY + padding).coerceAtMost(source.height - 1)
    return IconContentBounds(
        x = minX,
        y = minY,
        width = maxX - minX + 1,
        height = maxY - minY + 1,
    )
}

private fun averageCornerRgb(source: BufferedImage): Int {
    val colors = intArrayOf(
        source.getRGB(0, 0),
        source.getRGB(source.width - 1, 0),
        source.getRGB(0, source.height - 1),
        source.getRGB(source.width - 1, source.height - 1),
    )
    val red = colors.sumOf { it shr 16 and 0xff } / colors.size
    val green = colors.sumOf { it shr 8 and 0xff } / colors.size
    val blue = colors.sumOf { it and 0xff } / colors.size
    return AwtColor(red, green, blue).rgb
}

private fun findBrightContentBounds(source: BufferedImage): IconContentBounds? {
    var minX = source.width
    var minY = source.height
    var maxX = -1
    var maxY = -1
    var brightPixels = 0
    for (y in 0 until source.height) {
        for (x in 0 until source.width) {
            val rgb = source.getRGB(x, y)
            val red = rgb shr 16 and 0xff
            val green = rgb shr 8 and 0xff
            val blue = rgb and 0xff
            if (red >= 218 && green >= 218 && blue >= 218) {
                brightPixels += 1
                if (x < minX) minX = x
                if (y < minY) minY = y
                if (x > maxX) maxX = x
                if (y > maxY) maxY = y
            }
        }
    }
    if (brightPixels < source.width * source.height / 200 || maxX < minX || maxY < minY) {
        return null
    }
    return IconContentBounds(
        x = minX,
        y = minY,
        width = maxX - minX + 1,
        height = maxY - minY + 1,
    )
}

private fun isCloseToBackground(rgb: Int, background: Int): Boolean {
    val tolerance = 28
    return kotlin.math.abs((rgb shr 16 and 0xff) - (background shr 16 and 0xff)) <= tolerance &&
        kotlin.math.abs((rgb shr 8 and 0xff) - (background shr 8 and 0xff)) <= tolerance &&
        kotlin.math.abs((rgb and 0xff) - (background and 0xff)) <= tolerance
}

private fun createFallbackTrayImage(size: Int): Image {
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
    val graphics = image.createGraphics()
    graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    graphics.scale(size / 64.0, size / 64.0)

    // AWT/XEmbed tray hosts may flatten transparent pixels to white/black.
    // Use a self-contained badge so the icon is portable across tray themes.
    graphics.paint = GradientPaint(
        0f,
        0f,
        AwtColor(13, 25, 56),
        64f,
        64f,
        AwtColor(16, 92, 206),
    )
    graphics.fillRect(0, 0, 64, 64)

    graphics.paint = GradientPaint(
        7f,
        8f,
        AwtColor(43, 128, 236),
        59f,
        60f,
        AwtColor(255, 128, 31),
    )
    graphics.fillOval(4, 4, 56, 56)

    graphics.paint = GradientPaint(
        11f,
        9f,
        AwtColor(17, 165, 246),
        54f,
        58f,
        AwtColor(0, 36, 142),
    )
    graphics.fillOval(8, 8, 48, 48)

    val innerShield = Polygon(
        intArrayOf(32, 45, 44, 39, 32, 25, 20, 19),
        intArrayOf(16, 23, 36, 46, 53, 46, 36, 23),
        8,
    )
    graphics.paint = GradientPaint(
        20f,
        16f,
        AwtColor(255, 255, 255),
        44f,
        53f,
        AwtColor(200, 221, 246),
    )
    graphics.fillPolygon(innerShield)

    graphics.color = AwtColor(72, 107, 171)
    graphics.stroke = BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
    graphics.drawPolygon(innerShield)

    graphics.paint = GradientPaint(
        22f,
        24f,
        AwtColor(0, 204, 238),
        43f,
        47f,
        AwtColor(0, 63, 184),
    )
    val inner = Polygon(
        intArrayOf(32, 40, 39, 36, 32, 28, 25, 24),
        intArrayOf(24, 28, 36, 42, 46, 42, 36, 28),
        8,
    )
    graphics.fillPolygon(inner)

    graphics.color = AwtColor.WHITE
    graphics.stroke = BasicStroke(5.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
    graphics.drawLine(24, 34, 30, 40)
    graphics.drawLine(30, 40, 42, 27)

    graphics.color = AwtColor(255, 184, 69)
    graphics.fillOval(50, 36, 4, 4)
    graphics.fillOval(47, 47, 3, 3)
    graphics.dispose()
    return image
}

private class TrayPopupController {
    private var window: JWindow? = null
    private var hideTimer: Timer? = null

    fun toggle(
        anchor: Point,
        connectionActionLabel: String,
        findBestLabel: String,
        showWindowLabel: String,
        hideWindowLabel: String,
        exitLabel: String,
        connectionActionEnabled: Boolean,
        findBestEnabled: Boolean,
        onToggleConnection: () -> Unit,
        onFindBest: () -> Unit,
        onShowWindow: () -> Unit,
        onHideWindow: () -> Unit,
        onExit: () -> Unit,
    ) {
        SwingUtilities.invokeLater {
            if (window?.isVisible == true) {
                dismissNow()
                return@invokeLater
            }
            dismissNow()
            val popup = JWindow().apply {
                name = "vpn-control-tray-menu"
                setType(Window.Type.POPUP)
                isAlwaysOnTop = true
                focusableWindowState = false
                background = AwtColor(0, 0, 0, 0)
                contentPane = TrayMenuPanel(
                    connectionActionLabel = connectionActionLabel,
                    findBestLabel = findBestLabel,
                    showWindowLabel = showWindowLabel,
                    hideWindowLabel = hideWindowLabel,
                    exitLabel = exitLabel,
                    connectionActionEnabled = connectionActionEnabled,
                    findBestEnabled = findBestEnabled,
                    onToggleConnection = {
                        dismiss()
                        onToggleConnection()
                    },
                    onFindBest = {
                        dismiss()
                        onFindBest()
                    },
                    onShowWindow = {
                        dismiss()
                        onShowWindow()
                    },
                    onHideWindow = {
                        dismiss()
                        onHideWindow()
                    },
                    onExit = {
                        dismiss()
                        onExit()
                    },
                )
            }
            popup.pack()
            val bounds = GraphicsEnvironment
                .getLocalGraphicsEnvironment()
                .defaultScreenDevice
                .defaultConfiguration
                .bounds
            val x = (anchor.x - popup.width / 2)
                .coerceIn(bounds.x + 8, bounds.x + bounds.width - popup.width - 8)
            val preferredY = anchor.y - popup.height - 22
            val y = if (preferredY >= bounds.y + 8) {
                preferredY
            } else {
                (anchor.y + 22).coerceAtMost(bounds.y + bounds.height - popup.height - 8)
            }
            popup.setLocation(x, y)
            popup.isVisible = true
            popup.toFront()
            window = popup
            scheduleAutoHide()
        }
    }

    fun dismiss() {
        if (SwingUtilities.isEventDispatchThread()) {
            dismissNow()
        } else {
            SwingUtilities.invokeLater {
                dismissNow()
            }
        }
    }

    private fun dismissNow() {
        hideTimer?.stop()
        hideTimer = null
        window?.dispose()
        window = null
    }

    private fun scheduleAutoHide() {
        hideTimer?.stop()
        val timeoutMillis = System.getProperty("vpn.control.trayPopupAutoHideMillis")
            ?.toIntOrNull()
            ?.coerceIn(1_000, 120_000)
            ?: 6_000
        hideTimer = Timer(timeoutMillis) { dismiss() }.apply {
            isRepeats = false
            start()
        }
    }
}

private class TrayMenuPanel(
    connectionActionLabel: String,
    findBestLabel: String,
    showWindowLabel: String,
    hideWindowLabel: String,
    exitLabel: String,
    connectionActionEnabled: Boolean,
    findBestEnabled: Boolean,
    onToggleConnection: () -> Unit,
    onFindBest: () -> Unit,
    onShowWindow: () -> Unit,
    onHideWindow: () -> Unit,
    onExit: () -> Unit,
) : RoundedPanel() {
    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        add(row(showWindowLabel, true, onShowWindow))
        add(row(hideWindowLabel, true, onHideWindow))
        add(separator())
        add(row(connectionActionLabel, connectionActionEnabled, onToggleConnection))
        add(row(findBestLabel, findBestEnabled, onFindBest))
        add(separator())
        add(row(exitLabel, true, onExit))
    }

    private fun separator(): JSeparator {
        return JSeparator().apply {
            foreground = AwtColor(80, 112, 140)
            background = AwtColor(42, 58, 76)
            border = BorderFactory.createEmptyBorder(7, 0, 7, 0)
            alignmentX = LEFT_ALIGNMENT
        }
    }

    private fun row(
        title: String,
        enabled: Boolean,
        action: () -> Unit,
    ): JPanel {
        return TrayMenuRow(title, enabled, action).apply {
            alignmentX = LEFT_ALIGNMENT
        }
    }
}

private open class RoundedPanel : JPanel() {
    init {
        isOpaque = false
    }

    override fun paintComponent(graphics: Graphics) {
        val g = graphics.create() as Graphics2D
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g.paint = GradientPaint(
            0f,
            0f,
            AwtColor(18, 31, 45, 248),
            0f,
            height.toFloat(),
            AwtColor(7, 16, 30, 248),
        )
        g.fillRoundRect(0, 0, width - 1, height - 1, 18, 18)
        g.color = AwtColor(118, 162, 225, 130)
        g.stroke = BasicStroke(1.2f)
        g.drawRoundRect(0, 0, width - 1, height - 1, 18, 18)
        g.dispose()
        super.paintComponent(graphics)
    }
}

private class TrayMenuRow(
    title: String,
    enabled: Boolean,
    private val action: () -> Unit,
) : JPanel() {
    private var hovered = false

    init {
        isOpaque = false
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        border = BorderFactory.createEmptyBorder(9, 12, 9, 12)
        preferredSize = java.awt.Dimension(176, 38)
        maximumSize = java.awt.Dimension(176, 38)
        cursor = if (enabled) Cursor.getPredefinedCursor(Cursor.HAND_CURSOR) else Cursor.getDefaultCursor()

        add(JLabel(title).apply {
            foreground = if (enabled) AwtColor.WHITE else AwtColor(122, 139, 154)
            font = font.deriveFont(java.awt.Font.BOLD, 13f)
        })

        addMouseListener(
            object : MouseAdapter() {
                override fun mouseEntered(event: MouseEvent) {
                    if (enabled) {
                        hovered = true
                        repaint()
                    }
                }

                override fun mouseExited(event: MouseEvent) {
                    hovered = false
                    repaint()
                }

                override fun mouseReleased(event: MouseEvent) {
                    if (enabled) {
                        action()
                    }
                }
            },
        )
    }

    override fun paintComponent(graphics: Graphics) {
        val g = graphics.create() as Graphics2D
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        if (hovered) {
            g.color = AwtColor(72, 123, 181, 92)
            g.fillRoundRect(0, 3, width, height - 6, 14, 14)
        }
        g.dispose()
        super.paintComponent(graphics)
    }
}
