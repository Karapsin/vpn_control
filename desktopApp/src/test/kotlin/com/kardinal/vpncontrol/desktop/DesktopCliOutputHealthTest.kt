package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopCliOutputHealthTest {
    @Test fun windowsNeverWritesAProbeToMessagePipesOrUnknownPipeTypes() {
        for (flags in listOf(null, 4, 5)) {
            assertEquals(null, DesktopCliOutputHealth.probeBytePipe(flags) { error("No probe write permitted") })
        }
        for (flags in listOf(0, 1)) {
            var writes = 0
            assertEquals(232, DesktopCliOutputHealth.probeBytePipe(flags) { writes++; 232 })
            assertEquals(1, writes)
        }
    }

    @Test fun posixHealthPollsTheMatchingOutputDescriptorWithPolloutAndRejectsOnlyClosureBits() {
        val calls = mutableListOf<Pair<Int, Int>>()
        assertFalse(DesktopCliOutputHealth.isClosed(json = true, osName = "Linux", poll = { fd, events ->
            calls += fd to events
            0x0004 // POLLOUT: writable is healthy.
        }))
        assertFalse(DesktopCliOutputHealth.isClosed(json = false, osName = "Mac OS X", poll = { fd, events ->
            calls += fd to events
            0
        }))
        assertEquals(listOf(1 to 0x0004, 2 to 0x0004), calls)
    }

    @Test fun posixClosureBitsAndOnlyThoseReportClosedWhileNativeFailureIsUnknown() {
        for (bit in listOf(0x0008, 0x0010, 0x0020)) {
            assertTrue(DesktopCliOutputHealth.isClosed(json = true, osName = "Linux", poll = { _, _ -> bit }))
        }
        assertFalse(DesktopCliOutputHealth.isClosed(json = true, osName = "Linux", poll = { _, _ -> 0x0004 }))
        assertFalse(DesktopCliOutputHealth.isClosed(json = true, osName = "Linux", poll = { _, _ -> null }))
    }

    @Test fun windowsProbesTheSelectedWriteHandleAndOnlyTreatsEndedPipesAsClosed() {
        val handles = mutableListOf<Int>()
        for (json in listOf(true, false)) {
            for (code in listOf(null, 5, 6, 232, 109)) {
                assertEquals(code == 232 || code == 109,
                    DesktopCliOutputHealth.isClosed(json, "Windows 11",
                        poll = { _, _ -> error("No POSIX call on Windows") },
                        windowsWrite = { handle -> handles += handle; code }))
            }
        }
        assertEquals(List(5) { -11 } + List(5) { -12 }, handles)
    }
}
