package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.LocationConfigs
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SelectionMappingLogicTest {
    @Test
    fun matchesExactRawLocation() {
        val candidate = SelectionCandidate(
            rawLink = "socks://user:pass@127.0.0.1:1080#Local",
            sourceUrl = "",
            name = "Local",
            server = "127.0.0.1",
        )

        assertTrue(
            SelectionMappingLogic.matchesSelectedLocation(
                candidate = candidate,
                selectedRawLink = candidate.rawLink,
                selectedSourceUrl = "",
                selectedName = "",
                selectedServer = "",
            ),
        )
    }

    @Test
    fun matchesEquivalentStoredJsonAndRawLink() {
        val rawLink = "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&type=tcp#Local"
        val candidate = SelectionCandidate(
            rawLink = LocationConfigs.normalizeStoredReference(rawLink),
            sourceUrl = "",
            name = "Local",
            server = "example.com",
        )

        assertTrue(
            SelectionMappingLogic.matchesSelectedLocation(
                candidate = candidate,
                selectedRawLink = rawLink,
                selectedSourceUrl = "",
                selectedName = "",
                selectedServer = "",
            ),
        )
    }

    @Test
    fun matchesSubscriptionIdentityWhenRawLocationChanges() {
        val candidate = SelectionCandidate(
            rawLink = "socks://user:pass@127.0.0.2:1080#Office",
            sourceUrl = "https://example.com/sub.txt",
            name = "Office",
            server = "127.0.0.2",
        )

        assertTrue(
            SelectionMappingLogic.matchesSelectedLocation(
                candidate = candidate,
                selectedRawLink = "socks://user:pass@127.0.0.1:1080#Office",
                selectedSourceUrl = candidate.sourceUrl,
                selectedName = candidate.name,
                selectedServer = candidate.server,
            ),
        )
    }

    @Test
    fun doesNotUseIdentityFallbackForManualLocations() {
        val candidate = SelectionCandidate(
            rawLink = "socks://user:pass@127.0.0.2:1080#Office",
            sourceUrl = "",
            name = "Office",
            server = "127.0.0.2",
        )

        assertFalse(
            SelectionMappingLogic.matchesSelectedLocation(
                candidate = candidate,
                selectedRawLink = "socks://user:pass@127.0.0.1:1080#Office",
                selectedSourceUrl = "",
                selectedName = candidate.name,
                selectedServer = candidate.server,
            ),
        )
    }

    @Test
    fun selectedStoredKeyUsesJsonBeforeRawLink() {
        val rawLink = "socks://user:pass@127.0.0.1:1080#Local"
        val selectedJson = LocationConfigs.normalizeStoredReference("socks://user:pass@127.0.0.2:1080#Json")

        assertEquals(
            selectedJson,
            SelectionMappingLogic.selectedStoredKey(
                selectedProfileJson = selectedJson,
                selectedProfileRawLink = rawLink,
            ),
        )
    }
}
