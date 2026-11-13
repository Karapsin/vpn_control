package com.kardinal.vpncontrol.desktop

import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.User32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinUser
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary
import com.sun.jna.win32.W32APIOptions
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import kotlin.system.exitProcess
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.fail
import java.awt.SystemTray as AwtSystemTray

@Suppress("FunctionName")
private interface TrayAreaDesktopLibrary : StdCallLibrary {
    fun CreateDesktopW(name: WString, device: Pointer?, mode: Pointer?, flags: Int, access: Int, attributes: Pointer?): Pointer?
    fun CloseDesktop(desktop: Pointer): Boolean
    fun SetThreadDesktop(desktop: Pointer): Boolean
    fun GetProcessWindowStation(): Pointer?
    fun GetUserObjectInformationW(handle: Pointer, index: Int, info: CharArray, length: Int, needed: IntByReference): Boolean
}

/**
 * The native side of run 6c7250f6 (row windows-proxy-lifecycle.no-tray-close, 2.2.17): a GUI started on a desktop
 * with no Shell_TrayWnd. Each test makes its own private desktop of the test's window station, starts nothing else
 * there and closes it; nothing on the user's desktop is changed. The child JVM is the product's own AWT tray backend.
 */
class DesktopTrayNotificationAreaNativeTest {
    private val desktops by lazy {
        Native.load("user32", TrayAreaDesktopLibrary::class.java, W32APIOptions.DEFAULT_OPTIONS)
    }

    @Test
    fun theNotificationAreaIsReadOnTheCallersOwnDesktop() = privateDesktop { _, desktop ->
        // This thread's desktop: whatever the session has, the product reads what its window census lists.
        assertEquals(TASKBAR in topLevelClasses(), WindowsNotificationArea.present())
        val (classes, present) = onDesktop(desktop) { topLevelClasses() to WindowsNotificationArea.present() }
        assertFalse(TASKBAR in classes, "a new desktop lists no taskbar: $classes")
        assertFalse(present, "a desktop with no Shell_TrayWnd has no notification area")
    }

    @Test
    fun aGuiStartedOnADesktopWithoutANotificationAreaNeverMakesItsTrayAvailable() = privateDesktop { name, _ ->
        val root = Files.createTempDirectory("tray-area-native-")
        try {
            val result = runChild(root, windowStation() + "\\" + name)
            assertEquals("true", result.getProperty("awtSupported"), "AWT supports a tray there, as it did on 2.2.17")
            assertEquals("false", result.getProperty("area"))
            assertEquals("unavailable", result.getProperty("first"), "the product's own AWT backend: ${result}")
            assertEquals("", result.getProperty("later"), "never available afterwards either")
            assertEquals("0", result.getProperty("awtIcons"), "no icon was offered to a desktop without a notification area")
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun aGuiOnTheSessionDesktopHasItsTrayExactlyWhenTheTaskbarIsThere() {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("tray-area-native-")
        try {
            val taskbar = TASKBAR in topLevelClasses()
            val result = runChild(root, desktop = null)
            assertEquals(taskbar.toString(), result.getProperty("area"))
            assertEquals(if (taskbar) "available" else "unavailable", result.getProperty("first"), "result: $result")
            assertEquals("", result.getProperty("later"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun privateDesktop(body: (String, Pointer) -> Unit) {
        assumeTrue(Platform.isWindows())
        val name = "VcTrayArea-" + UUID.randomUUID().toString().replace("-", "")
        val desktop = desktops.CreateDesktopW(WString(name), null, null, 0, GENERIC_ALL, null)
            ?: fail("CreateDesktopW refused $name: ${Native.getLastError()}")
        try {
            body(name, desktop)
        } finally {
            desktops.CloseDesktop(desktop)
        }
    }

    /** [body] on a new thread that SetThreadDesktop moved to [desktop]; a thread with no window may move. */
    private fun <T> onDesktop(desktop: Pointer, body: () -> T): T {
        val outcome = AtomicReference<Result<T>>()
        val thread = Thread({
            outcome.set(runCatching {
                check(desktops.SetThreadDesktop(desktop)) { "SetThreadDesktop refused: ${Native.getLastError()}" }
                body()
            })
        }, "tray-area-native-desktop")
        thread.start()
        thread.join(THREAD_MILLIS)
        check(!thread.isAlive) { "the thread on the private desktop did not finish" }
        return outcome.get().getOrThrow()
    }

    private fun windowStation(): String {
        val station = desktops.GetProcessWindowStation() ?: fail("GetProcessWindowStation: ${Native.getLastError()}")
        val name = CharArray(256)
        check(desktops.GetUserObjectInformationW(station, UOI_NAME, name, name.size * 2, IntByReference())) {
            "GetUserObjectInformationW: ${Native.getLastError()}"
        }
        return Native.toString(name)
    }

    /** The product's AWT tray backend in a JVM of its own, started on [desktop] (null: this process's desktop). */
    private fun runChild(root: Path, desktop: String?): Properties {
        val java = Path.of(System.getProperty("java.home"), "bin", "java.exe").toString()
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        val result = root.resolve("result.properties")
        val log = root.resolve("child.log")
        val command = listOf(java, "-cp", classpath, DesktopTrayNotificationAreaNativeChild::class.java.name,
            result.toString(), log.toString()).joinToString(" ") { windowsArgument(it) }
        val startup = WinBase.STARTUPINFO().apply { lpDesktop = desktop }
        val process = WinBase.PROCESS_INFORMATION()
        check(Kernel32.INSTANCE.CreateProcessW(null, (command + "\u0000").toCharArray(), null, null, false,
            WinDef.DWORD(WinBase.CREATE_NO_WINDOW.toLong()), null, root.toString(), startup, process)) {
            "CreateProcessW refused the tray child: ${Native.getLastError()}"
        }
        try {
            if (Kernel32.INSTANCE.WaitForSingleObject(process.hProcess, CHILD_MILLIS) != WinBase.WAIT_OBJECT_0) {
                // Only the exact child this test started is ended.
                Kernel32.INSTANCE.TerminateProcess(process.hProcess, 1)
                Kernel32.INSTANCE.WaitForSingleObject(process.hProcess, THREAD_MILLIS.toInt())
                fail("the tray child did not finish within $CHILD_MILLIS ms: ${read(log)}")
            }
            val exit = IntByReference()
            check(Kernel32.INSTANCE.GetExitCodeProcess(process.hProcess, exit)) { "GetExitCodeProcess: ${Native.getLastError()}" }
            assertEquals(0, exit.value, "the tray child's exit; its log: ${read(log)}")
            return Properties().apply { Files.newBufferedReader(result).use { load(it) } }
        } finally {
            Kernel32.INSTANCE.CloseHandle(process.hThread)
            Kernel32.INSTANCE.CloseHandle(process.hProcess)
        }
    }

    private fun read(path: Path): String = if (Files.exists(path)) Files.readString(path) else "<no child log>"

    private companion object {
        const val TASKBAR = "Shell_TrayWnd"
        const val GENERIC_ALL = 0x10000000
        const val UOI_NAME = 2
        const val CHILD_MILLIS = 120_000
        const val THREAD_MILLIS = 60_000L

        /** The class of every top-level window of the calling thread's desktop: EnumWindows lists only that desktop. */
        fun topLevelClasses(): List<String> {
            val classes = mutableListOf<String>()
            // An empty desktop answers FALSE without an error; the list is what the callback saw either way.
            User32.INSTANCE.EnumWindows(WinUser.WNDENUMPROC { window, _ ->
                val name = CharArray(256)
                val length = User32.INSTANCE.GetClassName(window, name, name.size)
                if (length > 0) classes += String(name, 0, length)
                true
            }, null)
            return classes
        }

        /** One argument of a CreateProcessW command line, quoted as CommandLineToArgvW and the C runtime read it. */
        fun windowsArgument(value: String): String {
            if (value.isNotEmpty() && value.none { it == ' ' || it == '\t' || it == '"' }) return value
            val quoted = StringBuilder("\"")
            var backslashes = 0
            for (character in value) {
                when (character) {
                    '\\' -> backslashes++
                    '"' -> {
                        quoted.append("\\".repeat(backslashes * 2 + 1)).append('"')
                        backslashes = 0
                    }
                    else -> {
                        quoted.append("\\".repeat(backslashes)).append(character)
                        backslashes = 0
                    }
                }
            }
            return quoted.append("\\".repeat(backslashes * 2)).append('"').toString()
        }
    }
}

/**
 * The child of [DesktopTrayNotificationAreaNativeTest]: the product's AWT tray backend as DesktopTrayIcon installs
 * it, with three attempts 200 ms apart instead of sixty a second apart, reporting what it decided.
 */
internal object DesktopTrayNotificationAreaNativeChild {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val result = Path.of(arguments[0])
        val log = PrintStream(Files.newOutputStream(Path.of(arguments[1])), true, Charsets.UTF_8)
        System.setOut(log)
        System.setErr(log)
        val reports = LinkedBlockingQueue<String>()
        val handle = AtomicReference<DesktopTrayHandle?>()
        val awtSupported = runCatching { AwtSystemTray.isSupported() }.getOrDefault(false)
        val area = WindowsNotificationArea.present()
        val menu = TrayMenuState(
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
        val backend = AwtTrayBackend(
            retryPolicy = TrayRegistrationRetryPolicy(maxAttempts = 3, retryDelayMillis = 200),
            onLost = { reports.offer("lost") },
        )
        AsyncDesktopTrayBackendInstaller(DesktopTrayBackendInstaller(listOf(backend))).install(
            appTitle = { "VPN Control" },
            menuState = { menu },
            onAvailable = { reports.offer("available") },
            onUnavailable = { reports.offer("unavailable") },
            onComplete = handle::set,
        )
        val first = reports.poll(60, TimeUnit.SECONDS) ?: "none"
        Thread.sleep(2_500) // Two reads of the notification area after the first answer: nothing changes.
        val later = generateSequence { reports.poll() }.toList()
        val icons = runCatching { AwtSystemTray.getSystemTray().trayIcons.size }.getOrDefault(-1)
        SwingUtilities.invokeAndWait { handle.get()?.dispose() }
        val properties = Properties().apply {
            setProperty("awtSupported", awtSupported.toString())
            setProperty("area", area.toString())
            setProperty("first", first)
            setProperty("later", later.joinToString(","))
            setProperty("awtIcons", icons.toString())
        }
        Files.newOutputStream(result).use { properties.store(it, null) }
        log.flush()
        exitProcess(0)
    }
}
