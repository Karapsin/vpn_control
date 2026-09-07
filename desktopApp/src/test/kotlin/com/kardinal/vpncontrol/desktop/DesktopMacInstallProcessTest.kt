package com.kardinal.vpncontrol.desktop

import com.sun.jna.Pointer
import kotlin.test.*

class DesktopMacInstallProcessTest {
    @Test fun requiresExactNativeGenerationAndMatchingRealEffectiveSavedUser() {
        val process = DesktopMacInstallProcesses.read(123, Fake())
        assertEquals(501L, process.uid)
        assertEquals(1700000000L, process.startSeconds)
        assertEquals(654321L, process.startMicroseconds)
        for (api in listOf(Fake().apply { wrongPid = true }, Fake().apply { changed = true },
            Fake().apply { credentials = true }, Fake().apply { truncated = true })) {
            assertFails { DesktopMacInstallProcesses.read(123, api) }
        }
    }
    private class Fake : DesktopMacInstallProcesses.Api {
        var wrongPid = false
        var changed = false
        var credentials = false
        var truncated = false
        var reads = 0
        override fun proc_pidinfo(pid: Int, flavor: Int, argument: Long, buffer: Pointer, size: Int): Int {
            assertEquals(3, flavor); assertEquals(136, size)
            buffer.clear(size.toLong())
            buffer.setInt(12, if (wrongPid) 124 else pid)
            buffer.setInt(20, 501); buffer.setInt(28, 501); buffer.setInt(36, if (credentials) 0 else 501)
            buffer.setLong(120, 1700000000)
            buffer.setLong(128, if (changed && reads++ > 0) 654322 else 654321)
            return if (truncated) 135 else 136
        }
        override fun proc_pidpath(pid: Int, buffer: Pointer, size: Int): Int {
            val text = "/Applications/vpn-control.app/Contents/MacOS/vpn-control"
            buffer.setString(0, text, "UTF-8")
            return text.length + 1
        }
    }
}
