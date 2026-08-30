package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.DnsMode
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
                dns = DnsSettings(),
                routingRules = RoutingRules(ignoreRules = true),
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
    fun androidProxyOnlyConfigUsesSharedOutboundShapeForSupportedProtocols() {
        protocolProfiles().forEach { profile ->
            val config = SingBoxConfigFactory.buildProxyOnlyConfig(
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
    fun androidVpnConfigWithEmptyActiveRulesRoutesAllAppsThroughProxy() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(),
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
            dns = DnsSettings(),
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
    fun androidVpnConfigRoutesCustomDnsOverTheProxy() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(
                mode = DnsMode.CUSTOM_DOH,
                endpoint = "https://dns.example/dns-query",
            ),
            routingRules = RoutingRules(ignoreRules = true),
        )
        val root = parseConfig(config)
        val dnsServer = root.getValue("dns")
            .jsonObject
            .getValue("servers")
            .jsonArray
            .last()
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

        assertEquals("secure-dns", dnsServer.getValue("tag").jsonPrimitive.content)
        assertEquals("dns.example", dnsServer.getValue("server").jsonPrimitive.content)
        assertEquals("proxy", dnsServer.getValue("detour").jsonPrimitive.content)
        assertEquals("bootstrap-dns", dnsServer.getValue("domain_resolver").jsonPrimitive.content)
        assertTrue(directCidrs.contains("1.1.1.1/32"))
    }

    @Test
    fun androidVpnActiveVerificationInboundRoutesToProxyBeforeDirectRules() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = false,
                directDomainSuffixes = listOf("chatgpt.com"),
            ),
            activeVerificationPort = 24080,
        )
        val root = parseConfig(config)
        val inbounds = root.getValue("inbounds").jsonArray
        val routeRules = root.getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray
        val activeInbound = inbounds[1].jsonObject
        val activeProxyRule = routeRules[2].jsonObject
        val directDomainIndex = routeRules.indexOfFirstRuleWith("domain_suffix")

        assertEquals("active-verify-in", activeInbound.getValue("tag").jsonPrimitive.content)
        assertEquals(24080, activeInbound.getValue("listen_port").jsonPrimitive.content.toInt())
        assertEquals("active-verify-in", routeRules[1].jsonObject.getValue("inbound").jsonPrimitive.content)
        assertEquals("active-verify-in", activeProxyRule.getValue("inbound").jsonPrimitive.content)
        assertEquals("route", activeProxyRule.getValue("action").jsonPrimitive.content)
        assertEquals("proxy", activeProxyRule.getValue("outbound").jsonPrimitive.content)
        assertTrue(directDomainIndex > 2)
    }

    @Test
    fun androidVpnConfigPreservesUdp443ByDefault() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = false,
                blockQuicUdp443 = false,
            ),
        )
        val routeRules = parseConfig(config)
            .getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray

        assertEquals(-1, routeRules.indexOfQuicCompatibilityBlockRule())
    }

    @Test
    fun androidVpnConfigCanBlockUdp443ForQuicCompatibility() {
        val config = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(
                ignoreRules = false,
                blockQuicUdp443 = true,
                directDomainSuffixes = listOf("example.com"),
            ),
        )
        val routeRules = parseConfig(config)
            .getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray
        val blockIndex = routeRules.indexOfQuicCompatibilityBlockRule()
        val blockRule = routeRules[blockIndex].jsonObject
        val directDomainIndex = routeRules.indexOfFirstRuleWith("domain_suffix")

        assertEquals(2, blockIndex)
        assertEquals("udp", blockRule.getValue("network").jsonPrimitive.content)
        assertEquals(443, blockRule.getValue("port").jsonPrimitive.content.toInt())
        assertEquals("block", blockRule.getValue("outbound").jsonPrimitive.content)
        assertTrue(directDomainIndex > blockIndex)
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

    private fun JsonArray.indexOfQuicCompatibilityBlockRule(): Int {
        return indexOfFirst { element ->
            val rule = (element as? JsonObject) ?: return@indexOfFirst false
            rule["network"]?.jsonPrimitive?.content == "udp" &&
                rule["port"]?.jsonPrimitive?.content == "443" &&
                rule["outbound"]?.jsonPrimitive?.content == "block"
        }
    }
}
