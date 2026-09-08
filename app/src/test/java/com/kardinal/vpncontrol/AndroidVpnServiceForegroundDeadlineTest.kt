package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.vpn.AndroidVpnService
import com.kardinal.vpncontrol.vpn.AndroidVpnServiceStartAdmission
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AndroidVpnServiceForegroundDeadlineTest {
    @Test fun startPromotesBeforeDispatchEvenWhenValidationFails() {
        val events = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            AndroidVpnServiceStartAdmission.dispatch(AndroidVpnService.ACTION_START,
                { events += "foreground" }, {
                    check(events == listOf("foreground"))
                    events += "validation"
                    throw IllegalStateException("blocked validation")
                })
        }
        assertEquals(listOf("foreground", "validation"), events)
    }

    @Test fun stopDispatchDoesNotPromoteForeground() {
        val events = mutableListOf<String>()
        AndroidVpnServiceStartAdmission.dispatch(AndroidVpnService.ACTION_STOP,
            { events += "foreground" }, { events += "dispatch" })
        assertEquals(listOf("dispatch"), events)
    }

    @Test fun failedPromotionDoesNotDispatchServiceWork() {
        val events = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            AndroidVpnServiceStartAdmission.dispatch(AndroidVpnService.ACTION_START,
                { throw IllegalStateException("foreground unavailable") }, { events += "dispatch" })
        }
        assertEquals(emptyList<String>(), events)
    }
}
