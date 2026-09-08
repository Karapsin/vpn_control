package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import com.sun.jna.win32.StdCallLibrary

/** Native image/token authority; no executable or architecture property is consulted. */
internal class JnaWindowsVpnHelperNative(
    private val admission: WindowsAdmissionNative = JnaWindowsInstallAdmission(),
) : WindowsVpnHelperNative, WindowsAdmissionNative by admission {
    private val files = JnaWindowsInstallNative()
    private val tokens = mutableListOf<WinNT.HANDLE>()
    private val api: Api by lazy { check(Platform.isWindows()); Native.load("kernel32", Api::class.java) }

    private fun checked(value: Boolean) {
        if (!value) throw WindowsInstallNativeFailure(Kernel32.INSTANCE.GetLastError())
    }

    @Synchronized override fun currentSid(): String {
        val token = WinNT.HANDLEByReference()
        checked(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        val retained = requireNotNull(token.value)
        tokens += retained
        return try { Advapi32Util.getTokenAccount(retained).sidString }
        finally { checked(Kernel32.INSTANCE.CloseHandle(retained)); tokens.remove(retained) }
    }

    override fun currentProcess(): DesktopWindowsNativeOwnerImage {
        val process = Kernel32.INSTANCE.GetCurrentProcess()
        val pid = Kernel32.INSTANCE.GetProcessId(process).toLong() and 0xffffffffL
        val created = Memory(32).use { times ->
            checked(api.GetProcessTimes(process, times, times.share(8), times.share(16), times.share(24)))
            times.getLong(0)
        }
        return DesktopWindowsNativeOwnerImage(processImage(process),
            DesktopWindowsRuntimeResourceNativeOwner(pid, created, currentSid()))
    }

    override fun processImage(process: WinNT.HANDLE): String = Memory(32768L * 2).use { buffer ->
        val count = IntByReference(32768)
        checked(api.QueryFullProcessImageNameW(process, 0, buffer, count))
        require(count.value in 1 until 32768) { "UNAVAILABLE" }
        String(CharArray(count.value) { buffer.getShort(it.toLong() * 2).toInt().toChar() })
    }

    override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray {
        require(files.inspect(handle).size in 1..limit.toLong()) { "RESOURCE_EXHAUSTED" }
        return files.read(handle, limit)
    }

    override fun machine(handle: WindowsInstallNative.Handle): Int =
        DesktopWindowsVpnHelperPe.machine(files.inspect(handle).size) { offset, count -> exact(handle, offset, count) }

    override fun identity(handle: WindowsInstallNative.Handle): String = Memory(52).use { info ->
        checked(api.GetFileInformationByHandle(files.retainedHandle(handle), info))
        listOf(28L, 44L, 48L).joinToString("") { "%08x".format(info.getInt(it)) }
    }

    override fun executable(handle: WindowsInstallNative.Handle, maximum: Long): DesktopWindowsPinnedExecutable {
        val before = files.inspect(handle)
        val identity = identity(handle)
        val result = DesktopWindowsVpnHelperPe.inspect(before.size, maximum) { offset, count -> exact(handle, offset, count) }
        require(files.inspect(handle).size == before.size && identity(handle) == identity) { "CONFLICT" }
        return result
    }

    private fun exact(handle: WindowsInstallNative.Handle, offset: Long, count: Int): ByteArray {
        val bytes = ByteArray(count)
        var position = 0
        while (position < count) {
            val chunk = ByteArray(count - position)
            val received = files.readExportChunk(handle, offset + position, chunk, chunk.size)
            require(received > 0) { "CONFLICT" }
            chunk.copyInto(bytes, position, 0, received)
            position += received
        }
        return bytes
    }

    @Synchronized override fun close() {
        var failure: Exception? = null
        for (index in tokens.indices.reversed()) {
            try { checked(Kernel32.INSTANCE.CloseHandle(tokens[index])); tokens.removeAt(index) }
            catch (error: Exception) { failure = failure ?: error }
        }
        failure?.let { throw it }
    }

    private interface Api : StdCallLibrary {
        fun QueryFullProcessImageNameW(process: WinNT.HANDLE, flags: Int, buffer: Pointer, count: IntByReference): Boolean
        fun GetProcessTimes(process: WinNT.HANDLE, creation: Pointer, exit: Pointer, kernel: Pointer, user: Pointer): Boolean
        fun GetFileInformationByHandle(file: WinNT.HANDLE, information: Pointer): Boolean
    }
}
