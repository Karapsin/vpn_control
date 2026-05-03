package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class StatusMessagesTest {
    @Test
    fun encodeDecodeRoundTripsArgumentsWithSeparators() {
        val message = StatusMessages.encode(
            StatusMessageKey.RUNTIME_LOG,
            "/tmp/runtime:sing|box%25.log\nnext",
        )

        val decoded = StatusMessages.decode(message)

        assertEquals(StatusMessageKey.RUNTIME_LOG, decoded?.key)
        assertEquals(listOf("/tmp/runtime:sing|box%25.log\nnext"), decoded?.args)
    }

    @Test
    fun decodeRejectsUnknownPayloads() {
        assertNull(StatusMessages.decode("Runtime log: /tmp/runtime.log"))
        assertNull(StatusMessages.decode("vpn-control-status:v1:UNKNOWN_KEY"))
    }

    @Test
    fun locationsRefreshedUsesSingularAndPluralKeys() {
        assertEquals(StatusMessageKey.LOCATION_REFRESHED_COUNT, StatusMessages.decode(StatusMessages.locationsRefreshed(1))?.key)
        assertEquals(StatusMessageKey.LOCATIONS_REFRESHED_COUNT, StatusMessages.decode(StatusMessages.locationsRefreshed(2))?.key)
    }
}
