package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.Kernel32Util
import com.sun.jna.platform.win32.Shell32Util
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary

/**
 * Gives main the arguments a Windows jpackage launcher had before it restarted itself.
 *
 * Since JDK 17.0.10 (JDK-8301247) the launcher starts its own image again whenever PATH lacks
 * `<image>\app` and waits for it. Executor::args (jdk17u Executor.cpp:34-59) joins the arguments with
 * single spaces and quotes only a value holding a space or tab, so the child loses empty values and
 * embedded quotes, and a quoted value ending in a backslash swallows the values after it. The waiting
 * parent still holds the original command line. macOS and Linux launchers pass arguments unchanged.
 */
internal object DesktopWindowsLauncherArguments {
    /** One process's facts, read through one open handle; each is null when Windows did not give it. */
    data class Process(val image: String?, val createdAt: Long?, val commandLine: String?)

    interface Source {
        fun current(): Process
        fun parentPid(): Long?
        /** Null when the process can no longer be opened. */
        fun open(pid: Long): Process?
        /** Shell32 CommandLineToArgvW, argv[0] included. */
        fun split(commandLine: String): List<String>
    }

    /** Main's first step: anything unproven, and every other platform, keeps [received] unchanged. */
    fun forMain(
        received: Array<String>,
        osName: String = System.getProperty("os.name").orEmpty(),
        source: () -> Source = { JnaWindowsLauncherProcesses },
    ): Array<String> {
        if (!osName.startsWith("Windows", ignoreCase = true)) return received
        return runCatching { recover(received.toList(), source()) }.getOrNull()?.toTypedArray() ?: received
    }

    /** The restart parent's arguments, or null when this process is not its proven restart. */
    private fun recover(received: List<String>, windows: Source): List<String>? {
        val self = windows.current()
        val image = self.image ?: return null
        val born = self.createdAt ?: return null
        val parent = windows.parentPid()?.let(windows::open) ?: return null
        if (parent.image != image) return null
        // A reused PID belongs to a process created after this one, so only a later parent is refused; an equal
        // time is kept, as OpenJDK's ProcessHandleImpl keeps it. The real parent is earlier in practice: Windows
        // records creation times finer than 1 ms, and that parent runs before it creates this process.
        val parentBorn = parent.createdAt ?: return null
        if (parentBorn > born) return null
        return restored(received, image, parent.commandLine ?: return null, windows::split)
    }

    /** The parent's arguments only if jpackage's restart of them yields exactly [received]; never a merge. */
    fun restored(received: List<String>, program: String, parentCommandLine: String,
                 split: (String) -> List<String>): List<String>? {
        val original = split(parentCommandLine).drop(1)
        return original.takeIf { split(restartCommandLine(program, original)).drop(1) == received }
    }

    /** Executor::args: the launcher image then every argument, each through escapeArg, joined by one space. */
    fun restartCommandLine(program: String, arguments: List<String>): String =
        (listOf(program) + arguments).joinToString(" ", transform = ::escape)

    /** escapeArg: empty and already quoted values stay as they are; only a space or tab adds quotes. */
    fun escape(argument: String): String = when {
        argument.isEmpty() -> argument
        argument.length > 1 && argument.first() == '"' && argument.last() == '"' -> argument
        argument.any { it == ' ' || it == '\t' } -> "\"$argument\""
        else -> argument
    }
}

/** Thin reads behind [DesktopWindowsLauncherArguments.Source]; every decision stays in that object. */
private object JnaWindowsLauncherProcesses : DesktopWindowsLauncherArguments.Source {
    private const val processBasicInformation = 0
    private const val processCommandLineInformation = 60
    private const val firstCommandLineBytes = 4096
    private const val commandLineBytesLimit = 1 shl 17
    private val nt: DesktopWindowsNtProcessQuery by lazy {
        Native.load("ntdll", DesktopWindowsNtProcessQuery::class.java)
    }

    override fun current(): DesktopWindowsLauncherArguments.Process =
        Kernel32.INSTANCE.GetCurrentProcess().let { DesktopWindowsLauncherArguments.Process(image(it), createdAt(it), null) }

    /** PROCESS_BASIC_INFORMATION holds six pointer-sized fields; the parent is InheritedFromUniqueProcessId. */
    override fun parentPid(): Long? = Memory(6L * Native.POINTER_SIZE).use { information ->
        if (nt.NtQueryInformationProcess(Kernel32.INSTANCE.GetCurrentProcess(), processBasicInformation,
                information, 6 * Native.POINTER_SIZE, IntByReference()) != 0) null
        else Pointer.nativeValue(information.getPointer(5L * Native.POINTER_SIZE)).takeIf { it > 0 }
    }

    override fun open(pid: Long): DesktopWindowsLauncherArguments.Process? {
        val process = Kernel32.INSTANCE.OpenProcess(WinNT.PROCESS_QUERY_LIMITED_INFORMATION, false, pid.toInt())
            ?: return null
        try { return DesktopWindowsLauncherArguments.Process(image(process), createdAt(process), commandLine(process)) }
        finally { Kernel32.INSTANCE.CloseHandle(process) }
    }

    override fun split(commandLine: String): List<String> = Shell32Util.CommandLineToArgv(commandLine).toList()

    private fun image(process: WinNT.HANDLE): String = Kernel32Util.QueryFullProcessImageName(process, 0)

    private fun createdAt(process: WinNT.HANDLE): Long? {
        val created = WinBase.FILETIME()
        if (!Kernel32.INSTANCE.GetProcessTimes(process, created, WinBase.FILETIME(), WinBase.FILETIME(), WinBase.FILETIME()))
            return null
        return ((created.dwHighDateTime.toLong() shl 32) or (created.dwLowDateTime.toLong() and 0xffffffffL)).takeIf { it > 0 }
    }

    /** ProcessCommandLineInformation (Windows 8.1+) needs only PROCESS_QUERY_LIMITED_INFORMATION. */
    private fun commandLine(process: WinNT.HANDLE): String? {
        var size = firstCommandLineBytes
        while (true) {
            val needed = IntByReference()
            Memory(size.toLong()).use { buffer ->
                if (nt.NtQueryInformationProcess(process, processCommandLineInformation, buffer, size, needed) == 0)
                    return unicodeString(buffer, size)
            }
            // A too small first buffer reports the size it needs; any other failure ends here.
            if (size != firstCommandLineBytes || needed.value <= size || needed.value > commandLineBytesLimit) return null
            size = needed.value
        }
    }

    /** UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer } whose text must lie in [buffer]. */
    private fun unicodeString(buffer: Memory, size: Int): String? {
        val bytes = buffer.getShort(0).toInt() and 0xffff
        val text = Pointer.nativeValue(buffer.getPointer(Native.POINTER_SIZE.toLong()) ?: return null) -
            Pointer.nativeValue(buffer)
        if (bytes % 2 != 0 || text < 2L * Native.POINTER_SIZE || text + bytes > size) return null
        return String(CharArray(bytes / 2) { buffer.getShort(text + it * 2L).toInt().toChar() })
    }
}

/** JNA reflects this interface, so it cannot be private. */
internal interface DesktopWindowsNtProcessQuery : StdCallLibrary {
    fun NtQueryInformationProcess(process: WinNT.HANDLE, informationClass: Int, information: Pointer,
                                  length: Int, returnLength: IntByReference): Int
}
