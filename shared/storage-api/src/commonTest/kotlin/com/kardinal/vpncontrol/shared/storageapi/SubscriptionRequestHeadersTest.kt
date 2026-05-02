package com.kardinal.vpncontrol.shared.storageapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class SubscriptionRequestHeadersTest {
    @Test
    fun buildIncludesStableHwidWhenProvided() {
        val headers = SubscriptionRequestHeaders.build(
            userAgent = "VPNControl/1.0",
            accept = "text/plain, */*",
            subscriptionHwid = "  abc123  ",
        )

        assertEquals("VPNControl/1.0", headers["User-Agent"])
        assertEquals("text/plain, */*", headers["Accept"])
        assertEquals("abc123", headers[SubscriptionRequestHeaders.HWID_HEADER])
    }

    @Test
    fun buildOmitsBlankHwid() {
        val headers = SubscriptionRequestHeaders.build(
            userAgent = "VPNControl/1.0",
            accept = "*/*",
            subscriptionHwid = " ",
        )

        assertFalse(SubscriptionRequestHeaders.HWID_HEADER in headers)
    }
}
