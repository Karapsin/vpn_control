package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.data.HomeSshRouteConfigBuilder
import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ProxyProfile
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopProxyConfigFactoryTest {
    @Test
    fun buildProxyOnlyConfigUsesSingBoxThirteenCompatibleSniffRule() {
        val config = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
            listenPort = 40999,
        )

        val root = Json.parseToJsonElement(config).jsonObject
        val inbound = root.getValue("inbounds").jsonArray.single().jsonObject
        val routeRules = root.getValue("route").jsonObject.getValue("rules").jsonArray
        val sniffRule = routeRules.first().jsonObject

        assertEquals("mixed", inbound.getValue("type").jsonPrimitive.content)
        assertEquals("mixed-in", inbound.getValue("tag").jsonPrimitive.content)
        assertFalse("sniff" in inbound)
        assertEquals("mixed-in", sniffRule.getValue("inbound").jsonPrimitive.content)
        assertEquals("sniff", sniffRule.getValue("action").jsonPrimitive.content)
        assertEquals("1s", sniffRule.getValue("timeout").jsonPrimitive.content)
    }

    @Test
    fun buildVpnConfigUsesTunInboundAndProxyOutbound() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
        )

        val root = Json.parseToJsonElement(config).jsonObject
        val inbound = root.getValue("inbounds").jsonArray.single().jsonObject
        val outboundTags = root.getValue("outbounds")
            .jsonArray
            .map { it.jsonObject.getValue("tag").jsonPrimitive.content }

        assertEquals("tun", inbound.getValue("type").jsonPrimitive.content)
        assertEquals(
            DesktopProxyConfigFactory.DEFAULT_VPN_INTERFACE_NAME,
            inbound.getValue("interface_name").jsonPrimitive.content,
        )
        assertTrue(outboundTags.contains("proxy"))
        assertEquals("proxy", root.getValue("route").jsonObject.getValue("final").jsonPrimitive.content)
    }

    @Test
    fun buildVpnConfigUsesGvisorTunStackOnWindows() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
            osName = "Windows Server 2025",
        )

        val inbound = Json.parseToJsonElement(config).jsonObject
            .getValue("inbounds").jsonArray.single().jsonObject
        assertEquals("gvisor", inbound.getValue("stack").jsonPrimitive.content)
    }

    @Test
    fun buildVpnConfigChainsProxyAndBypassesThroughHomeSsh() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(directDomainSuffixes = listOf("home.example")),
            activeVerificationPort = 24080,
            homeRoute = homeOptions(),
        )
        val root = Json.parseToJsonElement(config).jsonObject
        val outbounds = root.getValue("outbounds").jsonArray.map { it.jsonObject }
        val byTag = outbounds.associateBy { it.getValue("tag").jsonPrimitive.content }
        val rules = root.getValue("route").jsonObject.getValue("rules").jsonArray.map { it.jsonObject }

        assertEquals(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG, byTag.getValue("proxy").string("detour"))
        assertEquals("socks", byTag.getValue(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG).string("type"))
        assertEquals(
            HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG,
            byTag.getValue(HomeSshRouteConfigBuilder.HOME_EGRESS_TAG).string("detour"),
        )
        assertEquals("ssh", byTag.getValue(HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG).string("type"))
        assertEquals(
            HomeSshRouteConfigBuilder.HOME_EGRESS_TAG,
            rules.first { "domain_suffix" in it }.string("outbound"),
        )
    }

    @Test
    fun buildVpnConfigRoutesOnlyDesktopProbeProcessesDirectBeforeDnsHijack() {
        val probePath = Path.of("/tmp/vpn-control-validation/vpn-control-probe-sing-box").toString()
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
            directProbeRouting = DesktopDirectProbeRouting(
                processNames = DesktopDirectProbeRouting.defaultProcessNames(),
                processPaths = listOf(probePath),
            ),
        )

        val routeRules = Json.parseToJsonElement(config)
            .jsonObject
            .getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray
        val processNameRuleIndex = routeRules.indexOfFirstRuleWith("process_name")
        val processPathRuleIndex = routeRules.indexOfFirstRuleWith("process_path")
        val dnsHijackRuleIndex = routeRules.indexOfFirst { rule ->
            rule.jsonObject["action"]?.jsonPrimitive?.content == "hijack-dns"
        }
        val processNames = routeRules[processNameRuleIndex]
            .jsonObject
            .getValue("process_name")
            .jsonArray
            .map { it.jsonPrimitive.content }
        val processPaths = routeRules[processPathRuleIndex]
            .jsonObject
            .getValue("process_path")
            .jsonArray
            .map { it.jsonPrimitive.content }

        assertTrue(processNameRuleIndex in 0 until dnsHijackRuleIndex)
        assertTrue(processPathRuleIndex in 0 until dnsHijackRuleIndex)
        assertFalse(processNames.contains("vpn-control"))
        assertTrue(processNames.contains("vpn-control-probe-sing-box"))
        assertFalse(processNames.contains("sing-box"))
        assertEquals(listOf(probePath), processPaths)
        assertEquals("direct", routeRules[processNameRuleIndex].jsonObject.getValue("outbound").jsonPrimitive.content)
        assertEquals("direct", routeRules[processPathRuleIndex].jsonObject.getValue("outbound").jsonPrimitive.content)
    }

    @Test
    fun buildVpnConfigRoutesCustomDnsOverTheProxy() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testProfile(),
            dns = DnsSettings(
                mode = DnsMode.CUSTOM_DOH,
                endpoint = "https://dns.example/dns-query",
            ),
            routingRules = RoutingRules(ignoreRules = true),
        )

        val root = Json.parseToJsonElement(config).jsonObject
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
    fun buildProxyOnlyConfigDoesNotInjectDesktopProbeRouting() {
        val config = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
            listenPort = 40999,
        )

        val routeRules = Json.parseToJsonElement(config)
            .jsonObject
            .getValue("route")
            .jsonObject
            .getValue("rules")
            .jsonArray

        assertEquals(-1, routeRules.indexOfFirstRuleWith("process_name"))
        assertEquals(-1, routeRules.indexOfFirstRuleWith("process_path"))
    }

    @Test
    fun buildProxyOnlyManagementInboundForcesSubscriptionThroughProxy() {
        val config = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = testProfile(),
            dns = DnsSettings(),
            routingRules = RoutingRules(directDomainSuffixes = listOf("subscription.example")),
            listenPort = 24080,
            managementProxyPort = 24081,
        )
        val root = Json.parseToJsonElement(config).jsonObject
        val inbounds = root.getValue("inbounds").jsonArray.map { it.jsonObject }
        val rules = root.getValue("route").jsonObject.getValue("rules").jsonArray.map { it.jsonObject }
        val managementRuleIndex = rules.indexOfFirst {
            it["inbound"]?.jsonPrimitive?.content == HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG &&
                it["outbound"]?.jsonPrimitive?.content == "proxy"
        }
        val directDomainIndex = rules.indexOfFirst { "domain_suffix" in it }

        assertEquals(2, inbounds.size)
        assertEquals(
            "24081",
            inbounds.first { it.string("tag") == HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG }
                .getValue("listen_port").jsonPrimitive.content,
        )
        assertTrue(managementRuleIndex in 0 until directDomainIndex)
    }

    @Test
    fun resolvedValidationServerPreservesImplicitTlsAndWebSocketHosts() {
        val profile = ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = "VLESS WS TLS",
            server = "edge.example.net",
            serverPort = 443,
            uuid = "00000000-0000-0000-0000-000000000000",
            network = "ws",
            flow = "",
            security = "tls",
            sni = "",
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "/ws",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://example",
        )

        val validationProfile = profile.withResolvedValidationServer("203.0.113.10")
        val config = DesktopProxyConfigFactory.buildProxyOnlyConfig(
            profile = validationProfile,
            dns = DnsSettings(),
            routingRules = RoutingRules(ignoreRules = true),
            listenPort = 40999,
        )
        val outbound = Json.parseToJsonElement(config)
            .jsonObject
            .getValue("outbounds")
            .jsonArray
            .first()
            .jsonObject
        val transportHeaders = outbound.getValue("transport")
            .jsonObject
            .getValue("headers")
            .jsonObject

        assertEquals("203.0.113.10", outbound.getValue("server").jsonPrimitive.content)
        assertEquals("edge.example.net", outbound.getValue("tls").jsonObject.getValue("server_name").jsonPrimitive.content)
        assertEquals("edge.example.net", transportHeaders.getValue("Host").jsonPrimitive.content)
    }

    private fun testProfile(): ProxyProfile {
        return ProxyProfile(
            protocol = ProxyProtocol.SOCKS,
            remarks = "Test SOCKS",
            server = "127.0.0.1",
            serverPort = 1080,
            username = "user",
            password = "pass",
            network = "tcp",
            flow = "",
            security = "",
            sni = "",
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "socks://user:pass@127.0.0.1:1080#Test%20SOCKS",
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

    private fun JsonObject.string(key: String): String = getValue(key).jsonPrimitive.content

    private fun JsonArray.indexOfFirstRuleWith(key: String): Int {
        return indexOfFirst { element ->
            (element as? JsonObject)?.containsKey(key) == true
        }
    }

    private companion object {
        const val TEST_HOST_KEY =
            "AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
    }
}
