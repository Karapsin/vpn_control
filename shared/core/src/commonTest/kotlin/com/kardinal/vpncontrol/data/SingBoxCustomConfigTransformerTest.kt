package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class SingBoxCustomConfigTransformerTest {
    @Test
    fun homeRouteTransformsAllKnownExternalPathsAndAddsManagementProxy() {
        val transformed = SingBoxCustomConfigTransformer.transform(
            rawConfig = """
                {
                  "dns": {"servers": [{"type": "https", "tag": "remote-dns", "server": "dns.example"}]},
                  "inbounds": [{"type": "tun", "tag": "tun-in"}],
                  "outbounds": [
                    {"type": "vless", "tag": "proxy", "server": "vpn.example", "server_port": 443, "uuid": "id"},
                    {"type": "direct", "tag": "direct"}
                  ],
                  "route": {
                    "final": "proxy",
                    "rule_set": [{"type": "remote", "tag": "remote-rules", "format": "source", "url": "https://rules.example/list.json"}],
                    "rules": [{"domain_suffix": ["direct.example"], "action": "route", "outbound": "direct"}]
                  }
                }
            """.trimIndent(),
            managementProxyPort = 24080,
            homeRoute = homeOptions(),
        )
        val root = Json.parseToJsonElement(transformed).jsonObject
        val inbounds = root.getValue("inbounds").jsonArray.map { it.jsonObject }
        val outbounds = root.getValue("outbounds").jsonArray.map { it.jsonObject }
        val byTag = outbounds.associateBy { it.getValue("tag").jsonPrimitive.content }
        val dnsServers = root.getValue("dns").jsonObject.getValue("servers").jsonArray.map { it.jsonObject }
        val ruleSet = root.getValue("route").jsonObject.getValue("rule_set").jsonArray.single().jsonObject

        assertTrue(inbounds.any {
            it["tag"]?.jsonPrimitive?.content == HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG &&
                it["listen_port"]?.jsonPrimitive?.content == "24080"
        })
        assertEquals(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG, byTag.getValue("proxy").string("detour"))
        assertEquals("socks", byTag.getValue("direct").string("type"))
        assertEquals(HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG, byTag.getValue("direct").string("detour"))
        assertEquals("10808", byTag.getValue("direct").getValue("server_port").jsonPrimitive.content)
        assertEquals(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG, dnsServers.first().string("detour"))
        assertTrue(dnsServers.any { it.string("tag") == SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG })
        assertEquals(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG, ruleSet.string("download_detour"))
    }

    @Test
    fun unknownOutboundAndEndpointFeaturesFailClosed() {
        assertFailsWith<IllegalStateException> {
            SingBoxCustomConfigTransformer.transform(
                rawConfig = """{"outbounds":[{"type":"mystery","tag":"proxy"}],"route":{"final":"proxy"}}""",
                managementProxyPort = 24080,
                homeRoute = homeOptions(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SingBoxCustomConfigTransformer.transform(
                rawConfig = """{"endpoints":[{"type":"wireguard","tag":"wg"}],"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"proxy"}}""",
                managementProxyPort = 24080,
                homeRoute = homeOptions(),
            )
        }
    }

    @Test
    fun customTypesAndEndpointsRemainUntouchedWhenHomeRouteIsOff() {
        val transformed = SingBoxCustomConfigTransformer.transform(
            rawConfig = """
                {
                  "endpoints": [{"type": "wireguard", "tag": "wg"}],
                  "outbounds": [{"type": "future-protocol", "tag": "future"}],
                  "route": {"final": "wg", "rules": [{"action": "route", "outbound": "future"}]}
                }
            """.trimIndent(),
            managementProxyPort = 24080,
        )
        val root = Json.parseToJsonElement(transformed).jsonObject

        assertEquals("wireguard", root.getValue("endpoints").jsonArray.single().jsonObject.string("type"))
        assertEquals("future-protocol", root.getValue("outbounds").jsonArray.first().jsonObject.string("type"))
        assertEquals("wg", root.getValue("route").jsonObject.string("final"))
    }

    @Test
    fun collisionsAndDetourCyclesAreRejected() {
        assertFailsWith<IllegalArgumentException> {
            SingBoxCustomConfigTransformer.transform(
                rawConfig = """{"inbounds":[{"type":"mixed","tag":"other","listen":"127.0.0.1","listen_port":24080}],"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"proxy"}}""",
                managementProxyPort = 24080,
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SingBoxCustomConfigTransformer.transform(
                rawConfig = """{"outbounds":[{"type":"socks","tag":"a","detour":"b","server":"127.0.0.1","server_port":1},{"type":"socks","tag":"b","detour":"a","server":"127.0.0.1","server_port":2}],"route":{"final":"a"}}""",
                managementProxyPort = 24080,
                homeRoute = homeOptions(),
            )
        }
    }

    @Test
    fun trustedDesktopProbeBypassUsesItsOwnDirectOutbound() {
        val transformed = SingBoxCustomConfigTransformer.transform(
            rawConfig = """{"outbounds":[{"type":"direct","tag":"proxy"}],"route":{"final":"proxy"}}""",
            managementProxyPort = 24080,
            homeRoute = homeOptions(),
            trustedDirectBypassRules = listOf(
                buildJsonObject {
                    put("process_name", "vpn-control-probe-sing-box")
                    put("action", "route")
                    put("outbound", SingBoxCustomConfigTransformer.TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG)
                },
            ),
        )
        val root = Json.parseToJsonElement(transformed).jsonObject
        val byTag = root.getValue("outbounds").jsonArray
            .map { it.jsonObject }
            .associateBy { it.string("tag") }
        val probeRule = root.getValue("route").jsonObject.getValue("rules").jsonArray
            .map { it.jsonObject }
            .first { "process_name" in it }

        assertEquals("socks", byTag.getValue("proxy").string("type"))
        assertEquals(
            "direct",
            byTag.getValue(SingBoxCustomConfigTransformer.TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG).string("type"),
        )
        assertEquals(
            SingBoxCustomConfigTransformer.TRUSTED_DIRECT_BYPASS_OUTBOUND_TAG,
            probeRule.string("outbound"),
        )
    }

    private fun homeOptions() = HomeSshRouteRuntimeOptions(
        settings = HomeSshRouteSettings(
            enabled = true,
            host = "ssh.example",
            port = 228,
            user = "vpn",
            hostKeys = listOf("ssh-ed25519 $TEST_HOST_KEY"),
        ),
        privateKeyPath = "/private/key",
    )

    private fun kotlinx.serialization.json.JsonObject.string(key: String): String =
        getValue(key).jsonPrimitive.content

    private companion object {
        const val TEST_HOST_KEY =
            "AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
    }
}
