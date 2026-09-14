package com.kardinal.vpncontrol.ui

import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AndroidVisualWindowGuardTest {
    @Test
    fun primarySystemUiAnrBlocksCaptureAndPreservesTheRawWindowDump() {
        val dump = """
            Window #6 Window{832d7e1 u0 Application Not Responding: com.android.systemui}:
              mDisplayId=0 rootTaskId=1
            raw-primary-window-dump
        """.trimIndent()

        val failure = try {
            AndroidVisualWindowGuard.requireNoPrimaryAnr(dump)
            fail("primary SystemUI ANR must block visual capture")
            error("unreachable")
        } catch (error: IllegalStateException) {
            error
        }

        assertTrue(failure.message.orEmpty().contains("Application Not Responding: com.android.systemui"))
        assertTrue(failure.message.orEmpty().contains("raw-primary-window-dump"))
    }

    @Test
    fun secondaryDisplayAnrDoesNotBlockPrimaryCapture() {
        val dump = """
            Window #8 Window{aaa u0 Application Not Responding: com.android.systemui}:
              mDisplayId=1 rootTaskId=1
        """.trimIndent()

        AndroidVisualWindowGuard.requireNoPrimaryAnr(dump)
    }

    @Test
    fun nonAnrPrimaryWindowDoesNotBlockCapture() {
        val dump = """
            Window #5 Window{bbb u0 StatusBar}:
              mDisplayId=0 rootTaskId=1
        """.trimIndent()

        AndroidVisualWindowGuard.requireNoPrimaryAnr(dump)
    }
}
