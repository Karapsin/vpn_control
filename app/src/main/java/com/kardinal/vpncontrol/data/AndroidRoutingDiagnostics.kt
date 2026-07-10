package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules

internal object AndroidRoutingDiagnostics {
    private val udp443PacketConnection = Regex(
        """inbound/tun\[tun-in\]: inbound packet connection to \S+:443\b""",
    )

    fun countUdp443PacketConnections(diagnosticsLog: String): Int {
        return udp443PacketConnection.findAll(diagnosticsLog).count()
    }

    fun buildSection(
        routingRules: RoutingRules,
        diagnosticsLog: String,
        lastBenchmarkSummary: String,
    ): String {
        val udp443Count = countUdp443PacketConnections(diagnosticsLog)
        val tcpVerificationOk = lastBenchmarkSummary.contains("test=ok") &&
            lastBenchmarkSummary.contains("test_codes=200")
        return listOf(
            "quic_udp_443_policy=${quicPolicy(routingRules)}",
            "recent_udp_443_packet_connections=$udp443Count",
            "active_verification_covers=tcp_only",
            "tcp_active_verification_ok=$tcpVerificationOk",
            "udp_443_warning=${udp443Warning(routingRules, udp443Count, tcpVerificationOk)}",
        ).joinToString(separator = "\n")
    }

    private fun quicPolicy(routingRules: RoutingRules): String {
        return if (routingRules.blockQuicUdp443 && !routingRules.ignoreRules) {
            "block_udp_443_force_tcp_fallback"
        } else {
            "preserve_app_protocols"
        }
    }

    private fun udp443Warning(
        routingRules: RoutingRules,
        udp443Count: Int,
        tcpVerificationOk: Boolean,
    ): String {
        val udp443Blocked = routingRules.blockQuicUdp443 && !routingRules.ignoreRules
        return if (!udp443Blocked && udp443Count > 0 && tcpVerificationOk) {
            "tcp_verification_ok_but_udp_443_app_traffic_not_verified"
        } else {
            "none"
        }
    }
}
