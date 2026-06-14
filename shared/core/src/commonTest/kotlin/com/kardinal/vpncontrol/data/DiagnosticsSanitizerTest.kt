package com.kardinal.vpncontrol.data

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFalse

class DiagnosticsSanitizerTest {
    @Test
    fun redactTextRemovesProxyLinksUrlPathsAndIdentifiers() {
        val raw = """
            url=https://example.com/subscription/token
            raw_link=vless://11111111-1111-4111-8111-111111111111@example.com:8443?pbk=secret#Name
            candidate vless://22222222-2222-4222-8222-222222222222@example.net:8443?pbk=secret#Name
            connection to 203.0.113.10:443 user: kardinal /home/kardinal/.vpn-control-desktop
        """.trimIndent()

        val redacted = DiagnosticsSanitizer.redactText(raw)

        assertContains(redacted, "https://example.com/<redacted>")
        assertContains(redacted, "raw_link=<redacted>")
        assertContains(redacted, "<vless-link-redacted>")
        assertContains(redacted, "<ip-redacted>")
        assertContains(redacted, "user: <user>")
        assertContains(redacted, "/home/<user>")
        assertFalse(redacted.contains("11111111-1111-4111-8111-111111111111"))
        assertFalse(redacted.contains("token"))
        assertFalse(redacted.contains("secret"))
        assertFalse(redacted.contains("kardinal"))
    }

    @Test
    fun summarizeSingBoxConfigKeepsShapeWithoutSecrets() {
        val config = """
            {
              "inbounds": [
                {"type": "tun", "tag": "tun-in"},
                {"type": "mixed", "tag": "active-verify-in", "listen_port": 42709}
              ],
              "outbounds": [
                {
                  "type": "vless",
                  "tag": "proxy",
                  "server": "secret.example.com",
                  "server_port": 8443,
                  "uuid": "11111111-1111-4111-8111-111111111111",
                  "tls": {
                    "server_name": "secret-sni.example.com",
                    "reality": {"public_key": "public-secret", "short_id": "short-secret"}
                  }
                },
                {"type": "direct", "tag": "direct"}
              ],
              "route": {"rules": [{"action": "sniff"}]},
              "dns": {"servers": [{"tag": "remote-dns", "server": "1.1.1.1"}]}
            }
        """.trimIndent()

        val summary = DiagnosticsSanitizer.summarizeSingBoxConfig(config)

        assertContains(summary, "config_present=true")
        assertContains(summary, "inbound_types=tun,mixed")
        assertContains(summary, "proxy_outbound_type=vless")
        assertContains(summary, "proxy_server_present=true")
        assertContains(summary, "proxy_server_port=8443")
        assertContains(summary, "outbound_count=2")
        assertContains(summary, "route_rules_count=1")
        assertContains(summary, "dns_servers_count=1")
        assertFalse(summary.contains("secret.example.com"))
        assertFalse(summary.contains("11111111-1111-4111-8111-111111111111"))
        assertFalse(summary.contains("public-secret"))
    }
}
