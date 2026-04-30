package com.kardinal.vpncontrol.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SingBoxConfigFactoryInstrumentedTest {
    @Test
    fun buildsVlessRealityOutboundWithTransport() {
        val config = JSONObject(
            SingBoxConfigFactory.buildProxyValidationConfig(
                profile = ProxyProfile(
                    protocol = ProxyProtocol.VLESS,
                    remarks = "VLESS",
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
                httpPort = 8080,
                dns = DnsSettings(enabled = false, value = ""),
            ),
        )

        val outbound = outbound(config)
        assertEquals("vless", outbound.getString("type"))
        assertEquals("xtls-rprx-vision", outbound.getString("flow"))
        assertEquals("ws", outbound.getString("network"))
        assertEquals("/ws", outbound.getJSONObject("transport").getString("path"))
        assertEquals("cdn.example.com", outbound.getJSONObject("transport").getJSONObject("headers").getString("Host"))
        val reality = outbound.getJSONObject("tls").getJSONObject("reality")
        assertTrue(outbound.getJSONObject("tls").getBoolean("enabled"))
        assertEquals("public-key", reality.getString("public_key"))
        assertEquals("abcd1234", reality.getString("short_id"))
    }

    @Test
    fun buildsTrojanGrpcOutbound() {
        val config = JSONObject(
            SingBoxConfigFactory.buildProxyValidationConfig(
                profile = ProxyProfile(
                    protocol = ProxyProtocol.TROJAN,
                    remarks = "Trojan",
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
                httpPort = 8080,
                dns = DnsSettings(enabled = false, value = ""),
            ),
        )

        val outbound = outbound(config)
        assertEquals("trojan", outbound.getString("type"))
        assertEquals("grpc", outbound.getString("network"))
        assertEquals("trojan-grpc", outbound.getJSONObject("transport").getString("service_name"))
        assertEquals("edge.example.com", outbound.getJSONObject("tls").getString("server_name"))
    }

    @Test
    fun buildsShadowsocksOutbound() {
        val config = JSONObject(
            SingBoxConfigFactory.buildProxyValidationConfig(
                profile = ProxyProfile(
                    protocol = ProxyProtocol.SHADOWSOCKS,
                    remarks = "SS",
                    server = "ss.example.com",
                    serverPort = 8388,
                    password = "ss-pass",
                    method = "aes-256-gcm",
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
                ),
                httpPort = 8080,
                dns = DnsSettings(enabled = false, value = ""),
            ),
        )

        val outbound = outbound(config)
        assertEquals("shadowsocks", outbound.getString("type"))
        assertEquals("aes-256-gcm", outbound.getString("method"))
        assertEquals("ss-pass", outbound.getString("password"))
        assertFalse(outbound.has("tls"))
    }

    @Test
    fun buildsVmessOutbound() {
        val config = JSONObject(
            SingBoxConfigFactory.buildProxyValidationConfig(
                profile = ProxyProfile(
                    protocol = ProxyProtocol.VMESS,
                    remarks = "VMess",
                    server = "vmess.example.com",
                    serverPort = 443,
                    uuid = "123e4567-e89b-12d3-a456-426614174000",
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
                httpPort = 8080,
                dns = DnsSettings(enabled = false, value = ""),
            ),
        )

        val outbound = outbound(config)
        assertEquals("vmess", outbound.getString("type"))
        assertEquals("auto", outbound.getString("security"))
        assertEquals(0, outbound.getInt("alter_id"))
        assertEquals("/vmess", outbound.getJSONObject("transport").getString("path"))
        assertTrue(outbound.getJSONObject("tls").getBoolean("enabled"))
    }

    @Test
    fun buildsSocksOutbound() {
        val config = JSONObject(
            SingBoxConfigFactory.buildProxyValidationConfig(
                profile = ProxyProfile(
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
                ),
                httpPort = 8080,
                dns = DnsSettings(enabled = false, value = ""),
            ),
        )

        val outbound = outbound(config)
        assertEquals("socks", outbound.getString("type"))
        assertEquals("5", outbound.getString("version"))
        assertEquals("user", outbound.getString("username"))
        assertEquals("pass", outbound.getString("password"))
        assertFalse(outbound.has("tls"))
    }

    @Test
    fun buildTunConfigLimitsVpnToAssignedAppsWhenRulesAreActive() {
        val config = JSONObject(
            SingBoxConfigFactory.buildTunConfig(
                profile = socksProfile(),
                dns = DnsSettings(enabled = false, value = ""),
                routingRules = RoutingRules(
                    ignoreRules = false,
                    proxyPackages = listOf("com.example.app"),
                ),
            ),
        )

        val inbound = config.getJSONArray("inbounds").getJSONObject(0)
        val includePackages = inbound.getJSONArray("include_package")
        assertEquals(1, includePackages.length())
        assertEquals("com.example.app", includePackages.getString(0))
    }

    @Test
    fun buildTunConfigRoutesAllAppsWhenAssignmentsAreEmpty() {
        val rawConfig = SingBoxConfigFactory.buildTunConfig(
            profile = socksProfile(),
            dns = DnsSettings(enabled = false, value = ""),
            routingRules = RoutingRules(
                ignoreRules = false,
                proxyPackages = emptyList(),
            ),
        )
        val config = JSONObject(rawConfig)

        val inbound = config.getJSONArray("inbounds").getJSONObject(0)
        assertFalse(inbound.has("include_package"))
        assertFalse(rawConfig.contains("__vpncontrol_no_assigned_apps__"))
    }

    @Test
    fun buildTunConfigRoutesAllAppsWhenRulesAreIgnored() {
        val config = JSONObject(
            SingBoxConfigFactory.buildTunConfig(
                profile = socksProfile(),
                dns = DnsSettings(enabled = false, value = ""),
                routingRules = RoutingRules(
                    ignoreRules = true,
                    proxyPackages = listOf("com.example.app"),
                ),
            ),
        )

        val inbound = config.getJSONArray("inbounds").getJSONObject(0)
        assertFalse(inbound.has("include_package"))
    }

    private fun outbound(config: JSONObject): JSONObject {
        return config.getJSONArray("outbounds").getJSONObject(0)
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
}
