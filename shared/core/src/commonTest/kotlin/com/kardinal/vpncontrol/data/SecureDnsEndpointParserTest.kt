package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SecureDnsEndpointParserTest {
    @Test
    fun normalizesDohAndAddsTheDefaultPath() {
        val result = SecureDnsEndpointParser.normalize(
            DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = " https://dns.example "),
        ).getOrThrow()

        assertEquals("https://dns.example/dns-query", result.endpoint)
    }

    @Test
    fun normalizesDotAndOmitsTheDefaultPort() {
        val result = SecureDnsEndpointParser.normalize(
            DnsSettings(mode = DnsMode.CUSTOM_DOT, endpoint = "tls://dns.example:853"),
        ).getOrThrow()

        assertEquals("tls://dns.example", result.endpoint)
    }

    @Test
    fun automaticModeClearsEndpointButPreservesMigrationNotice() {
        val result = SecureDnsEndpointParser.normalize(
            DnsSettings(
                mode = DnsMode.AUTOMATIC,
                endpoint = "ignored",
                legacyRawAddress = "9.9.9.9",
            ),
        ).getOrThrow()

        assertEquals("", result.endpoint)
        assertEquals("9.9.9.9", result.legacyRawAddress)
    }

    @Test
    fun rejectsPlaintextAndAmbiguousEndpoints() {
        val invalid = listOf(
            DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "http://dns.example/dns-query"),
            DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://user@dns.example/dns-query"),
            DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "https://dns.example/dns-query?x=1"),
            DnsSettings(mode = DnsMode.CUSTOM_DOT, endpoint = "tls://dns.example/path"),
            DnsSettings(mode = DnsMode.CUSTOM_DOT, endpoint = ""),
        )

        invalid.forEach { settings ->
            assertTrue(SecureDnsEndpointParser.normalize(settings).isFailure, settings.toString())
        }
    }
}
