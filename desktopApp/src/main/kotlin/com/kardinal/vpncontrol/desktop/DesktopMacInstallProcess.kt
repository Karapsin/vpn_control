package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer

/** Native process generation, not a rounded Java Instant or a PID-only liveness test. */
internal data class DesktopMacInstallProcess(val pid: Long, val uid: Long, val startSeconds: Long,
    val startMicroseconds: Long, val executable: String) {
    init {
        require(pid in 1..Int.MAX_VALUE && uid in 1..0xfffffffeL)
        require(startSeconds > 0 && startMicroseconds in 0..999999)
        require(executable.startsWith('/') && '\u0000' !in executable)
    }
}

internal object DesktopMacInstallProcesses {
    internal interface Api : Library {
        fun proc_pidinfo(pid: Int, flavor: Int, argument: Long, buffer: Pointer, size: Int): Int
        fun proc_pidpath(pid: Int, buffer: Pointer, size: Int): Int
    }
    private val native: Api by lazy {
        require(System.getProperty("os.name").startsWith("Mac", true) && Native.POINTER_SIZE == 8)
        Native.load("System", Api::class.java)
    }
    fun read(pid: Long): DesktopMacInstallProcess = read(pid, native)
    internal fun read(pid: Long, api: Api): DesktopMacInstallProcess {
        require(pid in 1..Int.MAX_VALUE)
        fun identity(): List<Long> = Memory(136).use { data ->
            // Darwin SDK proc_bsdinfo: PROC_PIDTBSDINFO=3, sizeof=136 on supported 64-bit Macs.
            require(api.proc_pidinfo(pid.toInt(), 3, 0, data, 136) == 136) { "Process identity unavailable" }
            fun unsigned(offset: Long) = data.getInt(offset).toLong() and 0xffffffffL
            require(unsigned(12) == pid && unsigned(20) == unsigned(28) && unsigned(20) == unsigned(36)) {
                "Unexpected process credentials"
            }
            listOf(unsigned(20), data.getLong(120), data.getLong(128))
        }
        val before = identity()
        val executable = Memory(4096).use { data ->
            val count = api.proc_pidpath(pid.toInt(), data, 4096)
            require(count in 1..4095) { "Process executable unavailable" }
            data.getString(0, "UTF-8")
        }
        require(identity() == before) { "Process generation changed" }
        return DesktopMacInstallProcess(pid, before[0], before[1], before[2], executable)
    }
}
