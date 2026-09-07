package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DesktopWindowsRuntimeResourceNativeOwnerTest {
    @Test fun rejectsNonAsciiDigitsInAnOtherwiseValidSid() {
        assertFailsWith<IllegalArgumentException> {
            DesktopWindowsRuntimeResourceNativeOwner(123, 134000000000000000, "S-1-\u0665-\u0661\u0668")
        }
    }

    @Test fun rejectsUnrepresentableNativeIdentityWithoutTruncation() {
        for (pid in listOf(0L, -1L, 0x100000000L)) assertFailsWith<IllegalArgumentException> {
            DesktopWindowsRuntimeResourceNativeOwner(pid, 1, "S-1-5-18")
        }
        assertFailsWith<IllegalArgumentException> { DesktopWindowsRuntimeResourceNativeOwner(1, 0, "S-1-5-18") }
        for (sid in listOf("S-1-05-18", "S-1-281474976710656-18", "S-1-5-4294967296", "S-1-5" + "-1".repeat(16))) {
            assertFailsWith<IllegalArgumentException> { DesktopWindowsRuntimeResourceNativeOwner(1, 1, sid) }
        }
    }

    @Test fun keepsTheCapturedTupleAndRedactsIncidentalRendering() {
        val owner = DesktopWindowsRuntimeResourceNativeOwner(0xffffffffL, Long.MAX_VALUE, "S-1-5-21-1-2-3-1000")
        assertEquals(0xffffffffL, owner.processId)
        assertEquals(Long.MAX_VALUE, owner.creationFileTime)
        assertEquals("S-1-5-21-1-2-3-1000", owner.sid)
        assertEquals("DesktopWindowsRuntimeResourceNativeOwner(<redacted>)", owner.toString())
    }
}
