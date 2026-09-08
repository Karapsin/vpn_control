package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.Structure
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinError
import com.sun.jna.ptr.IntByReference

/** Detects a detached CLI output consumer without emitting a protocol heartbeat. */
internal object DesktopCliOutputHealth {
    private const val pollOutput = 0x0004
    private const val pollError = 0x0008
    private const val pollHangup = 0x0010
    private const val pollInvalid = 0x0020
    private const val standardOutput = -11
    private const val standardError = -12
    private const val pipeFileType = 3
    private const val messagePipeType = 4

    private val posix: DesktopCliOutputPosixPoll by lazy {
        Native.load(Platform.C_LIBRARY_NAME, DesktopCliOutputPosixPoll::class.java)
    }

    /** Unknown/unsupported native inspection fails open; only proven detached output returns true. */
    fun isClosed(json: Boolean): Boolean = isClosed(json, System.getProperty("os.name"), ::pollRevents, ::windowsPipeError)

    internal fun isClosed(json: Boolean, osName: String, poll: (fd: Int, events: Int) -> Int?,
                          windowsWrite: (standardHandle: Int) -> Int? = { null }): Boolean {
        if (osName.startsWith("Windows", ignoreCase = true)) {
            return windowsWrite(if (json) standardOutput else standardError) in
                setOf(WinError.ERROR_NO_DATA, WinError.ERROR_BROKEN_PIPE)
        }
        return closed(poll(if (json) 1 else 2, pollOutput))
    }

    internal fun closed(revents: Int?): Boolean = revents != null && revents and (pollError or pollHangup or pollInvalid) != 0

    internal fun probeBytePipe(flags: Int?, write: () -> Int?): Int? =
        if (flags != null && flags and messagePipeType == 0) write() else null

    private fun pollRevents(fd: Int, events: Int): Int? = runCatching {
        DesktopCliOutputPollFd().let { descriptor ->
            descriptor.fd = fd
            descriptor.events = events.toShort()
            descriptor.write()
            if (posix.poll(descriptor, 1, 0) < 0) null
            else {
                descriptor.read()
                descriptor.revents.toInt() and 0xffff
            }
        }
    }.getOrNull()

    private fun windowsPipeError(standardHandle: Int): Int? = runCatching {
        val kernel = Kernel32.INSTANCE
        val handle = kernel.GetStdHandle(standardHandle)
        // Only confirmed byte pipes share the anonymous-pipe null-write behavior.
        // A message pipe may assign meaning to a zero-length write.
        if (kernel.GetFileType(handle) != pipeFileType) null
        else {
            val flags = IntByReference()
            val type = if (kernel.GetNamedPipeInfo(handle, flags, null, null, null)) flags.value else null
            probeBytePipe(type) {
                if (kernel.WriteFile(handle, ByteArray(1), 0, IntByReference(), null)) null
                else Native.getLastError()
            }
        }
    }.getOrNull()
}

/** JNA reflects this interface, so it cannot be private. */
internal interface DesktopCliOutputPosixPoll : Library {
    fun poll(fds: DesktopCliOutputPollFd, count: Long, timeoutMillis: Int): Int
}

/** C pollfd: int fd; short events; short revents. */
internal class DesktopCliOutputPollFd : Structure() {
    @JvmField var fd: Int = 0
    @JvmField var events: Short = 0
    @JvmField var revents: Short = 0
    override fun getFieldOrder(): List<String> = listOf("fd", "events", "revents")
}
