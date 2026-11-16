package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.win32.StdCallLibrary

/** Created by the ordinary owner before UAC, so an unacknowledged child cannot escape ownership. */
internal class DesktopWindowsNativeJob private constructor(
    private val api: Api,
    private val handle: WinNT.HANDLE,
) : AutoCloseable {
    private var closed = false
    val handleValue: Long get() = Pointer.nativeValue(handle.pointer)

    @Synchronized fun terminate(): Boolean = !closed && api.TerminateJobObject(handle, 1)

    @Synchronized fun isEmpty(): Boolean {
        if (closed) return true
        return Memory(48).use { accounting ->
            // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION has four LARGE_INTEGERs and four DWORDs.
            accounting.clear()
            api.QueryInformationJobObject(handle, 1, accounting, 48, null) && accounting.getInt(40) == 0
        }
    }

    /** Puts the process [pid] in this job; false when the process cannot be opened or the job refuses it. */
    @Synchronized fun assign(pid: Long): Boolean {
        if (closed) return false
        // PROCESS_SET_QUOTA | PROCESS_TERMINATE, the access AssignProcessToJobObject requires.
        val process = Kernel32.INSTANCE.OpenProcess(0x0101, false, pid.toInt()) ?: return false
        return try {
            api.AssignProcessToJobObject(handle, process)
        } finally {
            Kernel32.INSTANCE.CloseHandle(process)
        }
    }

    /** Ends whatever still runs in the job, then closes it; never throws. */
    @Synchronized fun release() {
        if (closed) return
        if (!isEmpty()) api.TerminateJobObject(handle, 1)
        Kernel32.INSTANCE.CloseHandle(handle)
        closed = true
    }

    @Synchronized override fun close() {
        if (closed) return
        check(isEmpty()) { "OUTCOME_UNKNOWN" }
        check(Kernel32.INSTANCE.CloseHandle(handle)) { "OUTCOME_UNKNOWN" }
        closed = true
    }

    companion object {
        fun create(): DesktopWindowsNativeJob {
            check(System.getProperty("os.name").startsWith("Windows", true))
            check(Native.POINTER_SIZE == 8) { "UNSUPPORTED" }
            val api = Native.load("kernel32", Api::class.java)
            val handle = requireNotNull(api.CreateJobObjectW(null, null)) { "UNAVAILABLE" }
            try {
                Memory(144).use { limits ->
                    // x64 JOBOBJECT_EXTENDED_LIMIT_INFORMATION. Exactly one non-breakaway child.
                    limits.clear()
                    limits.setInt(16, 0x2008) // KILL_ON_JOB_CLOSE | ACTIVE_PROCESS
                    limits.setInt(40, 1)
                    check(api.SetInformationJobObject(handle, 9, limits, 144)) { "UNAVAILABLE" }
                }
                return DesktopWindowsNativeJob(api, handle)
            } catch (failure: Throwable) {
                Kernel32.INSTANCE.CloseHandle(handle)
                throw failure
            }
        }
    }

    private interface Api : StdCallLibrary {
        fun CreateJobObjectW(security: Pointer?, name: WString?): WinNT.HANDLE?
        fun SetInformationJobObject(job: WinNT.HANDLE, kind: Int, information: Pointer, size: Int): Boolean
        fun QueryInformationJobObject(job: WinNT.HANDLE, kind: Int, information: Pointer, size: Int, returned: Pointer?): Boolean
        fun TerminateJobObject(job: WinNT.HANDLE, exitCode: Int): Boolean
        fun AssignProcessToJobObject(job: WinNT.HANDLE, process: WinNT.HANDLE): Boolean
    }
}
