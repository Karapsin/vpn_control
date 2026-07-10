package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRoutingDiagnosticsTest {
    @Test
    fun countsUdp443PacketConnectionsFromTunLogs() {
        val log = """
            libbox: inbound/tun[tun-in]: inbound packet connection to 172.19.250.2:53
            libbox: inbound/tun[tun-in]: inbound packet connection to 203.0.113.10:443
            libbox: inbound/tun[tun-in]: inbound connection to example.com:443
            libbox: inbound/tun[tun-in]: inbound packet connection to 198.51.100.20:443
        """.trimIndent()

        assertEquals(2, AndroidRoutingDiagnostics.countUdp443PacketConnections(log))
    }

    @Test
    fun warnsWhenTcpVerificationPassesButUdp443IsObservedAndPreserved() {
        val section = AndroidRoutingDiagnostics.buildSection(
            routingRules = RoutingRules(blockQuicUdp443 = false),
            diagnosticsLog = "libbox: inbound/tun[tun-in]: inbound packet connection to 203.0.113.10:443",
            lastBenchmarkSummary = "profile: tcp=32.4ms test=ok test_codes=200 score=394",
        )

        assertTrue(section.contains("quic_udp_443_policy=preserve_app_protocols"))
        assertTrue(section.contains("recent_udp_443_packet_connections=1"))
        assertTrue(section.contains("udp_443_warning=tcp_verification_ok_but_udp_443_app_traffic_not_verified"))
    }

    @Test
    fun doesNotWarnWhenUdp443CompatibilityBlockIsEnabled() {
        val section = AndroidRoutingDiagnostics.buildSection(
            routingRules = RoutingRules(blockQuicUdp443 = true),
            diagnosticsLog = "libbox: inbound/tun[tun-in]: inbound packet connection to 203.0.113.10:443",
            lastBenchmarkSummary = "profile: tcp=32.4ms test=ok test_codes=200 score=394",
        )

        assertTrue(section.contains("quic_udp_443_policy=block_udp_443_force_tcp_fallback"))
        assertTrue(section.contains("udp_443_warning=none"))
    }

    @Test
    fun warnsWhenUdp443BlockIsStoredButRulesAreDisabled() {
        val section = AndroidRoutingDiagnostics.buildSection(
            routingRules = RoutingRules(
                ignoreRules = true,
                blockQuicUdp443 = true,
            ),
            diagnosticsLog = "libbox: inbound/tun[tun-in]: inbound packet connection to 203.0.113.10:443",
            lastBenchmarkSummary = "profile: tcp=32.4ms test=ok test_codes=200 score=394",
        )

        assertTrue(section.contains("quic_udp_443_policy=preserve_app_protocols"))
        assertTrue(section.contains("udp_443_warning=tcp_verification_ok_but_udp_443_app_traffic_not_verified"))
    }
}
