package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class DnsSettingsTest {
    @Test
    fun restoresNewSecureDnsFieldsWithoutConsultingLegacyEnableFlag() {
        val restored = restoreDnsSettings(
            modeName = DnsMode.CUSTOM_DOH.name,
            endpoint = " https://dns.example/dns-query ",
            legacyRawAddress = "9.9.9.9",
            legacyEnabled = false,
        )

        assertEquals(
            DnsSettings(
                mode = DnsMode.CUSTOM_DOH,
                endpoint = "https://dns.example/dns-query",
                legacyRawAddress = "9.9.9.9",
            ),
            restored,
        )
    }

    @Test
    fun migratesLegacyEncryptedEndpointsToTheirMatchingMode() {
        assertEquals(
            DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://dns.example/dns-query"),
            restoreDnsSettings(null, "", "https://dns.example/dns-query", true),
        )
        assertEquals(
            DnsSettings(mode = DnsMode.CUSTOM_DOT, endpoint = "tls://dns.example:853"),
            restoreDnsSettings(null, "", "tls://dns.example:853", true),
        )
    }

    @Test
    fun migratesLegacyRawDnsToAutomaticWithAVisibleNoticeValue() {
        assertEquals(
            DnsSettings(mode = DnsMode.AUTOMATIC, legacyRawAddress = "9.9.9.9"),
            restoreDnsSettings(null, "", "9.9.9.9", true),
        )
    }

    @Test
    fun ignoresDisabledLegacyDns() {
        assertEquals(DnsSettings(), restoreDnsSettings(null, "", "9.9.9.9", false))
    }
}
