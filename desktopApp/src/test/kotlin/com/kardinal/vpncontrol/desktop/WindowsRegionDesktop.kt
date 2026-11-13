package com.kardinal.vpncontrol.desktop

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Guid
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Shell32Util
import com.sun.jna.platform.win32.User32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinReg
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.win32.W32APIOptions
import java.awt.GraphicsEnvironment
import java.awt.Rectangle
import java.awt.Robot
import java.awt.Toolkit
import java.awt.TrayIcon
import java.awt.image.BufferedImage
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/*
 * Thin Windows glue for NativeRegionCapture.kt: it reads native state into the pure types and
 * applies their plans. Every decision (target choice, placement, occlusion, stability, session
 * restore) lives in the pure logic, which is unit-tested on every host.
 */

@Suppress("FunctionName")
internal interface VisualDwmLibrary : StdCallLibrary {
    fun DwmGetWindowAttribute(window: WinDef.HWND, attribute: Int, value: WinDef.RECT, size: Int): Int
    fun DwmGetWindowAttribute(window: WinDef.HWND, attribute: Int, value: IntByReference, size: Int): Int
    fun DwmSetWindowAttribute(window: WinDef.HWND, attribute: Int, value: IntByReference, size: Int): Int
}

@Suppress("FunctionName")
internal interface VisualUserLibrary : StdCallLibrary {
    fun SystemParametersInfo(action: Int, parameter: Int, value: IntByReference, update: Int): Boolean
    fun SystemParametersInfo(action: Int, parameter: Int, value: Pointer?, update: Int): Boolean
    fun SystemParametersInfo(action: Int, parameter: Int, value: VisualAnimationInfo, update: Int): Boolean
    fun GetCaretBlinkTime(): Int
    fun SetCaretBlinkTime(milliseconds: Int): Boolean
    fun IsChild(parent: WinDef.HWND, window: WinDef.HWND): Boolean
    fun IsHungAppWindow(window: WinDef.HWND): Boolean
    fun GetDlgCtrlID(window: WinDef.HWND): Int
    fun ClientToScreen(window: WinDef.HWND, point: WinDef.POINT): Boolean
    fun SendMessageTimeout(
        window: WinDef.HWND,
        message: Int,
        wParam: WinDef.WPARAM,
        lParam: String?,
        flags: Int,
        timeout: Int,
        result: IntByReference?,
    ): WinDef.LRESULT
}

@Suppress("FunctionName")
internal interface VisualShellLibrary : StdCallLibrary {
    fun Shell_NotifyIconGetRect(identifier: VisualNotifyIconIdentifier, location: WinDef.RECT): Int
}

@Structure.FieldOrder("cbSize", "iMinAnimate")
internal class VisualAnimationInfo : Structure() {
    @JvmField var cbSize: Int = 8
    @JvmField var iMinAnimate: Int = 0
}

@Structure.FieldOrder("cbSize", "hWnd", "uID", "guidItem")
internal class VisualNotifyIconIdentifier : Structure() {
    @JvmField var cbSize: Int = 0
    @JvmField var hWnd: WinDef.HWND? = null
    @JvmField var uID: Int = 0
    @JvmField var guidItem: Guid.GUID = Guid.GUID()
}

internal class TrayIconLocation(val rect: RegionRect, val identity: JsonObject)

internal class WindowsRegionDesktop(private val robot: Robot) : RegionDesktop {
    private val user32 = User32.INSTANCE
    private val user by lazy { Native.load("user32", VisualUserLibrary::class.java, W32APIOptions.DEFAULT_OPTIONS) }
    private val dwm by lazy { Native.load("dwmapi", VisualDwmLibrary::class.java, W32APIOptions.DEFAULT_OPTIONS) }
    private val shell by lazy { Native.load("shell32", VisualShellLibrary::class.java, W32APIOptions.DEFAULT_OPTIONS) }

    val processId: Int = ProcessHandle.current().pid().toInt()

    override fun pause(millis: Long) = Thread.sleep(millis)

    override fun screen(): RegionRect = GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration
        .bounds.let { RegionRect.sized(it.x, it.y, it.width, it.height) }

    override fun workArea(): RegionRect {
        val configuration = GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice.defaultConfiguration
        val bounds = configuration.bounds
        val insets = Toolkit.getDefaultToolkit().getScreenInsets(configuration)
        return RegionRect(bounds.x + insets.left, bounds.y + insets.top, bounds.x + bounds.width - insets.right, bounds.y + bounds.height - insets.bottom)
    }

    /** Native rectangles are device pixels; they equal AWT and Robot coordinates only at 100%. */
    override fun scale(): Pair<Double, Double> = GraphicsEnvironment.getLocalGraphicsEnvironment().defaultScreenDevice
        .defaultConfiguration.defaultTransform.let { it.scaleX to it.scaleY }

    override fun captureScreen(screen: RegionRect): BufferedImage =
        robot.createScreenCapture(Rectangle(screen.left, screen.top, screen.width, screen.height))

    /** Every top-level window in z-order, topmost first. */
    override fun census(): List<NativeWindow> {
        val handles = mutableListOf<WinDef.HWND>()
        check(user32.EnumWindows(WinUser.WNDENUMPROC { window, _ -> handles += window; true }, null)) {
            "Windows top-level window census failed"
        }
        return handles.mapNotNull(::describe)
    }

    override fun window(handle: Long): NativeWindow? = describe(hwnd(handle))

    private fun className(window: WinDef.HWND): String {
        val buffer = CharArray(256)
        return String(buffer, 0, user32.GetClassName(window, buffer, buffer.size).coerceAtLeast(0))
    }

    private fun windowText(window: WinDef.HWND): String {
        val length = user32.GetWindowTextLength(window)
        if (length <= 0) return ""
        val buffer = CharArray(length + 1)
        return String(buffer, 0, user32.GetWindowText(window, buffer, buffer.size).coerceAtLeast(0))
    }

    override fun isHungAppWindow(handle: Long): Boolean = user.IsHungAppWindow(hwnd(handle))

    /** A WM_NULL round trip through the window's thread; SMTO_ABORTIFHUNG returns at once for a hung one. */
    override fun answersWithin(handle: Long, timeoutMillis: Int): Boolean =
        user32.SendMessageTimeout(
            hwnd(handle), WM_NULL, WinDef.WPARAM(0), WinDef.LPARAM(0), SMTO_ABORTIFHUNG, timeoutMillis, WinDef.DWORDByReference(),
        ).toLong() != 0L

    override fun childWindows(handle: Long): List<NativeControl> {
        val children = mutableListOf<WinDef.HWND>()
        user32.EnumChildWindows(hwnd(handle), WinUser.WNDENUMPROC { child, _ -> children += child; true }, null)
        return children.map { child ->
            NativeControl(handleOf(child), className(child), windowText(child), user.GetDlgCtrlID(child), user32.IsWindowVisible(child))
        }
    }

    override fun clientArea(handle: Long): RegionRect? {
        val window = hwnd(handle)
        val client = WinDef.RECT()
        val origin = WinDef.POINT(0, 0)
        if (!user32.GetClientRect(window, client) || !user.ClientToScreen(window, origin)) return null
        return RegionRect(origin.x + client.left, origin.y + client.top, origin.x + client.right, origin.y + client.bottom)
    }

    private fun describe(window: WinDef.HWND): NativeWindow? {
        if (!user32.IsWindow(window)) return null
        val process = IntByReference()
        user32.GetWindowThreadProcessId(window, process)
        val title = windowText(window)
        val visible = user32.IsWindowVisible(window)
        val style = user32.GetWindowLong(window, WinUser.GWL_STYLE)
        val windowRect = WinDef.RECT().also { user32.GetWindowRect(window, it) }.region()
        var bounds = windowRect
        var source = "window-rect"
        var cloaked = false
        if (visible) {
            val frame = WinDef.RECT()
            if (dwm.DwmGetWindowAttribute(window, DWMWA_EXTENDED_FRAME_BOUNDS, frame, frame.size()) == 0) {
                bounds = frame.region()
                source = "dwm-extended-frame-bounds"
            }
            val cloak = IntByReference()
            cloaked = dwm.DwmGetWindowAttribute(window, DWMWA_CLOAKED, cloak, 4) == 0 && cloak.value != 0
        }
        val owner = user32.GetWindow(window, WinDef.DWORD(GW_OWNER.toLong()))
        return NativeWindow(
            handle = handleOf(window),
            processId = process.value,
            className = className(window),
            title = title,
            visible = visible,
            cloaked = cloaked,
            minimized = style and WS_MINIMIZE != 0,
            bounds = bounds,
            windowRect = windowRect,
            ownerHandle = owner?.let(::handleOf) ?: 0,
            boundsSource = source,
        )
    }

    /** SetWindowPos for windows this process does not own through AWT. */
    fun moveForeign(handle: Long, move: PlacementMove, resize: Boolean) {
        val flags = SWP_NOZORDER or SWP_NOOWNERZORDER or SWP_NOACTIVATE or (if (resize) 0 else SWP_NOSIZE)
        val rect = move.windowRect
        check(user32.SetWindowPos(hwnd(handle), null, rect.left, rect.top, rect.width, rect.height, flags)) {
            "SetWindowPos failed for ${hexHandle(handle)}: ${Kernel32.INSTANCE.GetLastError()}"
        }
    }

    /** Puts [window] directly beneath [above] in z-order without activating either. */
    override fun stackBelow(window: Long, above: Long): Boolean =
        user32.SetWindowPos(hwnd(window), hwnd(above), 0, 0, 0, 0, SWP_NOMOVE or SWP_NOSIZE or SWP_NOACTIVATE or SWP_NOOWNERZORDER)

    /** Best effort: no DWM open/close/move transition while the capture owns the window. */
    override fun disableTransitions(handle: Long): Boolean =
        dwm.DwmSetWindowAttribute(hwnd(handle), DWMWA_TRANSITIONS_FORCEDISABLED, IntByReference(1), 4) == 0

    override fun bringToForeground(handle: Long, pause: () -> Unit): Boolean {
        val target = hwnd(handle)
        repeat(FOREGROUND_ATTEMPTS) {
            if (foregroundHandle() == handle) return true
            val foreground = user32.GetForegroundWindow()
            val current = Kernel32.INSTANCE.GetCurrentThreadId()
            val foregroundThread = foreground?.let { user32.GetWindowThreadProcessId(it, null) } ?: 0
            val attached = foregroundThread != 0 && foregroundThread != current &&
                user32.AttachThreadInput(WinDef.DWORD(current.toLong()), WinDef.DWORD(foregroundThread.toLong()), true)
            try {
                user32.BringWindowToTop(target)
                user32.SetForegroundWindow(target)
            } finally {
                if (attached) {
                    user32.AttachThreadInput(WinDef.DWORD(current.toLong()), WinDef.DWORD(foregroundThread.toLong()), false)
                }
            }
            pause()
        }
        return foregroundHandle() == handle
    }

    override fun foregroundHandle(): Long = user32.GetForegroundWindow()?.let(::handleOf) ?: 0

    /** Keyboard focus of the target's GUI thread; focus must be the target or one of its descendants. */
    override fun focus(handle: Long): JsonObject {
        val target = hwnd(handle)
        val thread = user32.GetWindowThreadProcessId(target, null)
        val info = WinUser.GUITHREADINFO()
        info.cbSize = info.size()
        val read = thread != 0 && user32.GetGUIThreadInfo(thread, info)
        val focus = info.hwndFocus?.let(::handleOf) ?: 0
        val inside = read && focus != 0L && (focus == handle || user.IsChild(target, hwnd(focus)))
        return buildJsonObject {
            put("read", read)
            put("focus", hexHandle(focus))
            put("focus_class", if (focus == 0L) "" else window(focus)?.className.orEmpty())
            put("focus_inside_target", inside)
            put("caret", hexHandle(info.hwndCaret?.let(::handleOf) ?: 0))
        }
    }

    /** Shows focus rectangles and accelerators on the target and its children. */
    override fun showKeyboardCues(handle: Long) {
        user32.SendMessageTimeout(
            hwnd(handle), WM_UPDATEUISTATE,
            WinDef.WPARAM(((UISF_HIDEFOCUS or UISF_HIDEACCEL) shl 16 or UIS_CLEAR).toLong()),
            WinDef.LPARAM(0), SMTO_ABORTIFHUNG, 2_000, WinDef.DWORDByReference(),
        )
    }

    override fun parkCursor(x: Int, y: Int): Boolean {
        robot.mouseMove(x, y)
        val point = WinDef.POINT()
        return user32.GetCursorPos(point) && point.x == x && point.y == y
    }

    /** Closes a hosted runner's leftover paging-file warning; the occlusion guard decides what remains. */
    override fun dismissHostedSystemProperties(pause: () -> Unit): List<String> {
        if (System.getenv("VPN_CONTROL_VISUAL_PROVIDER") != "hosted") return emptyList()
        fun residue() = census().filter { it.visible && it.title.startsWith("System Properties", ignoreCase = true) }
        return dismissForeignResidue(
            maxAttempts = 20,
            residue = { residue().map(NativeWindow::describe) },
            dismiss = {
                residue().forEach { window ->
                    user32.PostMessage(hwnd(window.handle), WinUser.WM_CLOSE, WinDef.WPARAM(0), WinDef.LPARAM(0))
                }
            },
            pause = pause,
        )
    }

    fun taskbar(): NativeWindow? = census().firstOrNull { it.className == WindowsRegionScenes.TASKBAR_CLASS && it.visible }

    /** The notification-area rectangle of this process's AWT tray icon (hWnd + uID identity). */
    fun trayIconRect(icon: TrayIcon): Pair<RegionRect?, JsonObject> {
        val id = awtTrayIconId(icon)
        val messageWindows = census().filter {
            it.processId == processId && it.className == WindowsRegionScenes.AWT_TRAY_MESSAGE_WINDOW_CLASS
        }
        val identity = buildJsonObject {
            put("kind", "notification-icon")
            put("locator", "Shell_NotifyIconGetRect")
            put("process_id", processId)
            put("uid", id)
            put("message_window", messageWindows.singleOrNull()?.let { hexHandle(it.handle) } ?: "")
            put("message_windows", messageWindows.size)
        }
        val messageWindow = messageWindows.singleOrNull() ?: return null to identity
        val identifier = VisualNotifyIconIdentifier().apply {
            hWnd = hwnd(messageWindow.handle)
            uID = id
            cbSize = size()
        }
        val rect = WinDef.RECT()
        val result = shell.Shell_NotifyIconGetRect(identifier, rect)
        return (if (result == 0) rect.region() else null) to identity
    }

    /**
     * Windows 11 keeps new notification icons in the overflow; promote this process's icon.
     * Explorer records the icon's entry asynchronously after it is added, so wait (bounded) for it.
     */
    fun promoteTrayIcon(id: Int): AppliedSessionSetting? {
        if (!Advapi32Util.registryKeyExists(WinReg.HKEY_CURRENT_USER, NOTIFY_ICON_SETTINGS)) return null
        val executable = ProcessHandle.current().info().command().orElse("")
        var selected = emptyList<NotifyIconEntry>()
        for (poll in 1..NOTIFY_ICON_ENTRY_POLLS) {
            selected = selectNotifyIconEntries(notifyIconEntries(), executable, id, ::knownFolderPath)
            if (selected.isNotEmpty()) break
            pause(250)
        }
        if (selected.isEmpty()) return null
        selected.forEach { entry ->
            Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, "$NOTIFY_ICON_SETTINGS\\${entry.key}", "IsPromoted", 1)
        }
        return AppliedSessionSetting(
            "notify-icon-promoted",
            selected.joinToString { "${it.key}=${it.promoted ?: "absent"}" },
            "1",
        ) {
            selected.forEach { entry ->
                val path = "$NOTIFY_ICON_SETTINGS\\${entry.key}"
                if (entry.promoted == null) {
                    Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, path, "IsPromoted")
                } else {
                    Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, path, "IsPromoted", entry.promoted)
                }
            }
        }
    }

    private fun notifyIconEntries(): List<NotifyIconEntry> =
        Advapi32Util.registryGetKeys(WinReg.HKEY_CURRENT_USER, NOTIFY_ICON_SETTINGS).map { key ->
            val path = "$NOTIFY_ICON_SETTINGS\\$key"
            NotifyIconEntry(
                key = key,
                executablePath = registryString(path, "ExecutablePath").orEmpty(),
                uid = registryInt(path, "UID"),
                promoted = registryInt(path, "IsPromoted"),
            )
        }

    /** Caret blink, animations, keyboard cues, transparency and theme for the capture session. */
    fun sessionSettings(): List<Pair<String, SessionSetting>> = listOf(
        "caret-blink-ms" to sessionSetting("caret-blink-ms", INFINITE_BLINK, { user.GetCaretBlinkTime() }) { value ->
            check(user.SetCaretBlinkTime(value)) { "SetCaretBlinkTime failed" }
        },
        "keyboard-cues" to spiFlag("keyboard-cues", SPI_GETKEYBOARDCUES, SPI_SETKEYBOARDCUES, true),
        "client-area-animation" to spiFlag("client-area-animation", SPI_GETCLIENTAREAANIMATION, SPI_SETCLIENTAREAANIMATION, false),
        "menu-animation" to spiFlag("menu-animation", SPI_GETMENUANIMATION, SPI_SETMENUANIMATION, false),
        "combobox-animation" to spiFlag("combobox-animation", SPI_GETCOMBOBOXANIMATION, SPI_SETCOMBOBOXANIMATION, false),
        "listbox-smooth-scrolling" to spiFlag("listbox-smooth-scrolling", SPI_GETLISTBOXSMOOTHSCROLLING, SPI_SETLISTBOXSMOOTHSCROLLING, false),
        "selection-fade" to spiFlag("selection-fade", SPI_GETSELECTIONFADE, SPI_SETSELECTIONFADE, false),
        "tooltip-animation" to spiFlag("tooltip-animation", SPI_GETTOOLTIPANIMATION, SPI_SETTOOLTIPANIMATION, false),
        "window-animation" to sessionSetting("window-animation", 0, {
            VisualAnimationInfo().also { info ->
                info.cbSize = info.size()
                check(user.SystemParametersInfo(SPI_GETANIMATION, info.size(), info, 0)) { "SPI_GETANIMATION failed" }
            }.iMinAnimate
        }) { value ->
            val info = VisualAnimationInfo().also { it.cbSize = it.size(); it.iMinAnimate = value }
            check(user.SystemParametersInfo(SPI_SETANIMATION, info.size(), info, SPIF_SENDCHANGE)) { "SPI_SETANIMATION failed" }
        },
        "transparency" to personalizeValue("transparency", "EnableTransparency", 0),
        "system-light-theme" to personalizeValue("system-light-theme", "SystemUsesLightTheme", 1),
        "apps-light-theme" to personalizeValue("apps-light-theme", "AppsUseLightTheme", 1),
    )

    private fun spiFlag(name: String, get: Int, set: Int, capture: Boolean): SessionSetting =
        sessionSetting(name, capture, {
            val value = IntByReference()
            check(user.SystemParametersInfo(get, 0, value, 0)) { "SystemParametersInfo($get) failed" }
            value.value != 0
        }) { value ->
            check(user.SystemParametersInfo(set, 0, if (value) Pointer.createConstant(1) else null, SPIF_SENDCHANGE)) {
                "SystemParametersInfo($set) failed"
            }
        }

    private fun personalizeValue(name: String, value: String, capture: Int): SessionSetting =
        sessionSetting<Int?>(name, capture, { registryInt(PERSONALIZE, value) }) { next ->
            if (next == null) {
                Advapi32Util.registryDeleteValue(WinReg.HKEY_CURRENT_USER, PERSONALIZE, value)
            } else {
                Advapi32Util.registrySetIntValue(WinReg.HKEY_CURRENT_USER, PERSONALIZE, value, next)
            }
            user.SendMessageTimeout(
                WinDef.HWND(Pointer.createConstant(HWND_BROADCAST)), WM_SETTINGCHANGE, WinDef.WPARAM(0),
                "ImmersiveColorSet", SMTO_ABORTIFHUNG, 5_000, null,
            )
        }

    private fun registryInt(key: String, value: String): Int? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, key, value)) {
            Advapi32Util.registryGetIntValue(WinReg.HKEY_CURRENT_USER, key, value)
        } else {
            null
        }

    private fun registryString(key: String, value: String): String? =
        if (Advapi32Util.registryValueExists(WinReg.HKEY_CURRENT_USER, key, value)) {
            runCatching { Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, key, value) }.getOrNull()
        } else {
            null
        }

    private fun knownFolderPath(guid: String): String? =
        runCatching { Shell32Util.getKnownFolderPath(Guid.GUID.fromString("{$guid}")) }.getOrNull()

    private fun WinDef.RECT.region(): RegionRect = RegionRect(left, top, right, bottom)

    companion object {
        private const val DWMWA_TRANSITIONS_FORCEDISABLED = 3
        private const val DWMWA_EXTENDED_FRAME_BOUNDS = 9
        private const val DWMWA_CLOAKED = 14
        private const val GW_OWNER = 4
        private const val WS_MINIMIZE = 0x20000000
        private const val SWP_NOSIZE = 0x0001
        private const val SWP_NOMOVE = 0x0002
        private const val SWP_NOZORDER = 0x0004
        private const val SWP_NOACTIVATE = 0x0010
        private const val SWP_NOOWNERZORDER = 0x0200
        private const val WM_NULL = 0x0000
        private const val WM_SETTINGCHANGE = 0x001A
        private const val WM_UPDATEUISTATE = 0x0128
        private const val UIS_CLEAR = 2
        private const val UISF_HIDEFOCUS = 0x1
        private const val UISF_HIDEACCEL = 0x2
        private const val SMTO_ABORTIFHUNG = 0x0002
        private const val HWND_BROADCAST = 0xFFFFL
        private const val SPIF_SENDCHANGE = 0x0002
        private const val SPI_GETANIMATION = 0x0048
        private const val SPI_SETANIMATION = 0x0049
        private const val SPI_GETMENUANIMATION = 0x1002
        private const val SPI_SETMENUANIMATION = 0x1003
        private const val SPI_GETCOMBOBOXANIMATION = 0x1004
        private const val SPI_SETCOMBOBOXANIMATION = 0x1005
        private const val SPI_GETLISTBOXSMOOTHSCROLLING = 0x1006
        private const val SPI_SETLISTBOXSMOOTHSCROLLING = 0x1007
        private const val SPI_GETKEYBOARDCUES = 0x100A
        private const val SPI_SETKEYBOARDCUES = 0x100B
        private const val SPI_GETSELECTIONFADE = 0x1014
        private const val SPI_SETSELECTIONFADE = 0x1015
        private const val SPI_GETTOOLTIPANIMATION = 0x1016
        private const val SPI_SETTOOLTIPANIMATION = 0x1017
        private const val SPI_GETCLIENTAREAANIMATION = 0x1042
        private const val SPI_SETCLIENTAREAANIMATION = 0x1043
        private const val FOREGROUND_ATTEMPTS = 10
        private const val NOTIFY_ICON_ENTRY_POLLS = 20
        private const val PERSONALIZE = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"
        private const val NOTIFY_ICON_SETTINGS = "Control Panel\\NotifyIconSettings"

        /** GetCaretBlinkTime/SetCaretBlinkTime use INFINITE (0xFFFFFFFF) for "does not blink". */
        const val INFINITE_BLINK = -1

        fun hwnd(handle: Long): WinDef.HWND = WinDef.HWND(Pointer(handle))

        fun handleOf(window: WinDef.HWND): Long = Pointer.nativeValue(window.pointer)

        /** java.awt.TrayIcon.id is the uID AWT passes to Shell_NotifyIcon with its message window. */
        fun awtTrayIconId(icon: TrayIcon): Int =
            TrayIcon::class.java.getDeclaredField("id").apply { isAccessible = true }.getInt(icon)
    }
}
