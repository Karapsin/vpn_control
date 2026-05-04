package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SingBoxConfigFactoryParityTest {
    @Test
    fun androidVpnConfigUsesSharedOutboundShapeForSupportedProtocols() {
        protocolProfiles().forEach { profile ->
            val config = SingBoxConfigFactory.buildTunConfig(
                profile = profile,
                dns = DnsSettings(enabled = false, value = ""),
                routingRules = RoutingRules(ignoreRules = true),
            )

            assertEquals(
                SingBoxOutboundBuilder.buildOutbound(profile),
                proxyOutbound(config),
            )
        }
    }

    @Test
    fun androidProxyOnlyConfigUsesSharedOutboundShapeForSupportedProtocols() {
        protocolProfiles().forEach { profile ->
            val config = SingBoxConfigFactory.buildProxyOnlyConfig(
                profile = profile,
                dns = DnsSettings(enabled = false, value = ""),
                routingRules = RoutingRules(ignoreRules = true),
                listenPort = 2080,
            )

            assertEquals(
                SingBoxOutboundBuilder.buildOutbound(profile),
                proxyOutbound(config),
            )
        }
    }

    @Test
    fun androidVpnConfigWithEmptyActiveRulesRoutesAllAppsThroughProxy() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(enabled = false, value = ""),
            routingRules = RoutingRules(
                ignoreRules = false,
                proxyPackages = emptyList(),
                directDomainSuffixes = emptyList(),
                ruleSets = emptyList(),
            ),
        )
        val root = parseConfig(config)
        val inbound = root.getValue("inbounds").jsonArray.single().jsonObject
        val route = root.getValue("route").jsonObject
        val routeRules = route.getValue("rules").jsonArray

        assertEquals("proxy", route.getValue("final").jsonPrimitive.content)
        assertFalse("include_package" in inbound)
        assertFalse("rule_set" in route)
        assertEquals(-1, routeRules.indexOfFirstRuleWith("domain_suffix"))
        assertEquals(-1, routeRules.indexOfFirstRuleWith("rule_set"))
    }

    @Test
    fun androidVpnConfigWithProxyPackagesLimitsTunInbound() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(enabled = false, value = ""),
            routingRules = RoutingRules(
                ignoreRules = false,
                proxyPackages = listOf("org.example.browser", "org.example.chat"),
            ),
        )
        val inbound = parseConfig(config)
            .getValue("inbounds")
            .jsonArray
            .single()
            .jsonObject
        val packages = inbound.getValue("include_package").jsonArray.map { it.jsonPrimitive.content }

        assertEquals(listOf("org.example.browser", "org.example.chat"), packages)
    }

    @Test
    fun androidVpnConfigRoutesCustomDnsDirect() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(enabled = true, value = "9.9.9.9"),
            routingRules = RoutingRules(ignoreRules = true),
        )
        val root = parseConfig(config)
        val dnsServer = root.getValue("dns")
            .jsonObject
            .getValue("servers")
            .jsonArray
            .single()
            .jsonObject
        val directCidrs = root.getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray
            .first { rule -> rule.jsonObject.containsKey("ip_cidr") }
            .jsonObject
            .getValue("ip_cidr")
            .jsonArray
            .map { it.jsonPrimitive.content }

        assertEquals("custom-dns", dnsServer.getValue("tag").jsonPrimitive.content)
        assertEquals("9.9.9.9", dnsServer.getValue("server").jsonPrimitive.content)
        assertTrue(directCidrs.contains("9.9.9.9/32"))
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
