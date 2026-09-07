package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.QrExportPolicy
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.RoutingRules
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingQrExportTest {
    @Test fun smallPayloadAndExactByteCountMatchTheExistingExport() {
        val rules = RoutingRules(directDomainSuffixes = listOf("東京.example", "emoji😀.test"))
        val timestamp = "2026-09-07T00:00:00Z"
        val expected = RoutingRulesTransfer.export(rules, timestamp).content
        val result = AndroidRoutingQrExport.prepare(rules, timestamp)
        assertEquals(expected, result.payload)
        assertEquals(QrExportPolicy.byteCount(expected).toLong(), result.byteCount)
    }

    @Test fun largeExportRetainsNoWholePayloadAndStillCountsEveryUtf8Byte() {
        val suffix = "x".repeat(200)
        val rules = RoutingRules(directDomainSuffixes = List(12_000) { "d$it.$suffix.test" })
        val timestamp = "2026-09-07T00:00:00Z"
        val result = AndroidRoutingQrExport.prepare(rules, timestamp)
        assertNull(result.payload)
        assertTrue(result.byteCount > 2 * 1024 * 1024)
        assertEquals(RoutingRulesTransfer.export(rules, timestamp).content.toByteArray().size.toLong(), result.byteCount)
    }
}
