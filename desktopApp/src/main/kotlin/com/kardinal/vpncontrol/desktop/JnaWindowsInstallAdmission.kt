package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary

/** Direct native calls only: normal GUI/CLI admission starts no shell, compiler or elevation helper. */
internal class JnaWindowsInstallAdmission : WindowsAdmissionNative {
    private val files = JnaWindowsInstallNative()
    private val extra: Api by lazy { check(Platform.isWindows()); Native.load("kernel32", Api::class.java) }
    override fun currentSid(): String {
        check(Platform.isWindows())
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        return try { Advapi32Util.getTokenAccount(token.value).sidString }
        finally { Kernel32.INSTANCE.CloseHandle(token.value) }
    }
    override fun programData() = files.programData()
    override fun openDirectory(path: String) = files.open(path, WindowsInstallNative.INSPECT, shareDelete = false)
    override fun children(path: String): List<String> = java.nio.file.Files.newDirectoryStream(java.nio.file.Path.of(path)).use { entries ->
        // Bounded discovery only; inability to find a witness fails closed, never weakens policy.
        entries.asSequence().take(4096).map { it.fileName.toString() }.toList()
    }
    override fun openGate(path: String) = files.open(path, WindowsInstallNative.READ, shareDelete = false)
    override fun inspect(handle: WindowsInstallNative.Handle) = files.inspect(handle)
    override fun persistentAcl(handle: WindowsInstallNative.Handle): Boolean {
        val flags = IntByReference()
        checked(extra.GetVolumeInformationByHandleW(files.retainedHandle(handle), null, 0, null, null, flags, null, 0))
        return flags.value and 8 != 0
    }
    override fun canonicalPath(handle: WindowsInstallNative.Handle): String = Memory(32768L * 2).use { output ->
        val size = extra.GetFinalPathNameByHandleW(files.retainedHandle(handle), output, 32768, 0)
        require(size in 1 until 32768) { "Installation identity unavailable" }
        utf16(output, size)
    }
    override fun invariantUppercase(value: String): String {
        require(value.isNotEmpty() && '\u0000' !in value)
        val locale = WString("")
        val input = WString(value)
        val size = extra.LCMapStringEx(locale, 0x200, input, value.length, null, 0, null, null, null)
        require(size in 1..65536) { "Installation identity unavailable" }
        return Memory(size.toLong() * 2).use { output ->
            check(extra.LCMapStringEx(locale, 0x200, input, value.length, output, size, null, null, null) == size)
            // Positive cchSrc produces no NUL. Never use getWideString/StringBuilder here.
            utf16(output, size)
        }
    }
    override fun lockShared(handle: WindowsInstallNative.Handle): Boolean {
        if (extra.LockFileEx(files.retainedHandle(handle), 1, 0, 1, 0, WinBase.OVERLAPPED())) return true
        val error = Kernel32.INSTANCE.GetLastError()
        if (error == 33) return false
        throw WindowsInstallNativeFailure(error)
    }
    override fun readGate(handle: WindowsInstallNative.Handle) = files.read(handle, 18)
    override fun unlockShared(handle: WindowsInstallNative.Handle) {
        checked(extra.UnlockFileEx(files.retainedHandle(handle), 0, 1, 0, WinBase.OVERLAPPED()))
    }
    override fun close(handle: WindowsInstallNative.Handle) = files.close(handle)
    private fun checked(ok: Boolean) { if (!ok) throw WindowsInstallNativeFailure(Kernel32.INSTANCE.GetLastError()) }
    private fun utf16(pointer: Pointer, size: Int) = String(CharArray(size) { pointer.getShort(it.toLong() * 2).toInt().toChar() })
    private interface Api : StdCallLibrary {
        fun GetFinalPathNameByHandleW(handle: WinNT.HANDLE, output: Pointer, capacity: Int, flags: Int): Int
        fun LCMapStringEx(locale: WString, flags: Int, input: WString, inputLength: Int, output: Pointer?, capacity: Int,
            version: Pointer?, reserved: Pointer?, sort: Pointer?): Int
        fun GetVolumeInformationByHandleW(handle: WinNT.HANDLE, name: Pointer?, nameSize: Int, serial: IntByReference?,
            componentSize: IntByReference?, flags: IntByReference, fileSystem: Pointer?, fileSystemSize: Int): Boolean
        fun LockFileEx(handle: WinNT.HANDLE, flags: Int, reserved: Int, bytesLow: Int, bytesHigh: Int, overlapped: WinBase.OVERLAPPED): Boolean
        fun UnlockFileEx(handle: WinNT.HANDLE, reserved: Int, bytesLow: Int, bytesHigh: Int, overlapped: WinBase.OVERLAPPED): Boolean
    }
}
