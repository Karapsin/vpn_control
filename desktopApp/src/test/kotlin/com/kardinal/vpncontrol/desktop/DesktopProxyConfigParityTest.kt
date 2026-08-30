package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.data.SingBoxOutboundBuilder
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class DesktopProxyConfigParityTest {
    @Test
    fun desktopVpnConfigUsesSharedOutboundShapeForSupportedProtocols() {
        protocolProfiles().forEach { profile ->
            val config = DesktopProxyConfigFactory.buildVpnConfig(
                profile = profile,
                dns = DnsSettings(),
                routingRules = RoutingRules(ignoreRules = true),
                directProbeRouting = DesktopDirectProbeRouting(),
            )

            assertEquals(
                SingBoxOutboundBuilder.buildOutbound(
                    profile,
                    domainResolverTag = "bootstrap-dns",
                ),
                proxyOutbound(config),
            )
        }
    }

    @Test
    fun desktopProxyOnlyConfigUsesSharedOutboundShapeForSupportedProtocols() {
        protocolProfiles().forEach { profile ->
            val config = DesktopProxyConfigFactory.buildProxyOnlyConfig(
                profile = profile,
                dns = DnsSettings(),
                routingRules = RoutingRules(ignoreRules = true),
                listenPort = 2080,
            )

            assertEquals(
                SingBoxOutboundBuilder.buildOutbound(
                    profile,
                    domainResolverTag = "bootstrap-dns",
                ),
                proxyOutbound(config),
            )
        }
    }

    @Test
    fun desktopVpnConfigWithEmptyActiveRulesRoutesEverythingThroughProxy() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = socksProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = false,
                proxyPackages = emptyList(),
                directDomainSuffixes = emptyList(),
                ruleSets = emptyList(),
            ),
            directProbeRouting = DesktopDirectProbeRouting(),
        )
        val root = parseConfig(config)
        val route = root.getValue("route").jsonObject
        val routeRules = route.getValue("rules").jsonArray

        assertEquals("proxy", route.getValue("final").jsonPrimitive.content)
        assertFalse("rule_set" in route)
        assertEquals(-1, routeRules.indexOfFirstRuleWith("domain_suffix"))
        assertEquals(-1, routeRules.indexOfFirstRuleWith("rule_set"))
    }

    private fun protocolProfiles(): List<ProxyProfile> {
        return listOf(
            ProxyProfile(
                protocol = ProxyProtocol.VLESS,
                remarks = "VLESS Reality WS",
                server = "vless.example.com",
                serverPort = 443,
                uuid = "123e4567-e89b-12d3-a456-426614174000",
                network = "ws",
                flow = "xtls-rprx-vision",
                security = "reality",
                sni = "edge.example.com",
                fingerprint = "chrome",
                publicKey = "public-key",
                shortId = "abcd1234",
                path = "/ws",
                hostHeader = "cdn.example.com",
                serviceName = "",
                headerType = "none",
                rawLink = "",
            ),
            ProxyProfile(
                protocol = ProxyProtocol.TROJAN,
                remarks = "Trojan gRPC",
                server = "trojan.example.com",
                serverPort = 443,
                password = "secret",
                network = "grpc",
                flow = "",
                security = "tls",
                sni = "edge.example.com",
                fingerprint = "chrome",
                publicKey = "",
                shortId = "",
                path = "",
                hostHeader = "",
                serviceName = "trojan-grpc",
                headerType = "none",
                rawLink = "",
            ),
            ProxyProfile(
                protocol = ProxyProtocol.SHADOWSOCKS,
                remarks = "Shadowsocks",
                server = "ss.example.com",
                serverPort = 8388,
                password = "ss-pass",
                method = "aes-256-gcm",
                network = "udp",
                flow = "",
                security = "",
                sni = "",
                fingerprint = "chrome",
                publicKey = "",
                shortId = "",
                path = "",
                hostHeader = "",
                serviceName = "",
                headerType = "none",
                rawLink = "",
            ),
            ProxyProfile(
                protocol = ProxyProtocol.VMESS,
                remarks = "VMess WS",
                server = "vmess.example.com",
                serverPort = 443,
                uuid = "123e4567-e89b-12d3-a456-426614174001",
                network = "ws",
                flow = "",
                security = "tls",
                sni = "edge.example.com",
                fingerprint = "chrome",
                publicKey = "",
                shortId = "",
                path = "/vmess",
                hostHeader = "cdn.example.com",
                serviceName = "",
                headerType = "none",
                alterId = 0,
                vmessSecurity = "auto",
                rawLink = "",
            ),
            socksProfile(),
        )
    }

    private fun socksProfile(): ProxyProfile {
        return ProxyProfile(
            protocol = ProxyProtocol.SOCKS,
            remarks = "SOCKS",
            server = "socks.example.com",
            serverPort = 1080,
            username = "user",
            password = "pass",
            network = "tcp",
            flow = "",
            security = "",
            sni = "",
            fingerprint = "chrome",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "none",
            rawLink = "",
        )
    }

    private fun proxyOutbound(config: String): JsonObject {
        return parseConfig(config)
            .getValue("outbounds")
            .jsonArray
            .first()
            .jsonObject
    }

    private fun parseConfig(config: String): JsonObject {
        return Json.parseToJsonElement(config).jsonObject
    }

    private fun JsonArray.indexOfFirstRuleWith(key: String): Int {
        return indexOfFirst { element ->
            (element as? JsonObject)?.containsKey(key) == true
        }
    }
}
