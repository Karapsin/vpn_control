package com.kardinal.vpncontrol.data

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProxyParserInstrumentedTest {
    @Test
    fun parsesTrojanLink() {
        val link =
            "trojan://secret@example.com:443?security=tls&sni=edge.example.com&type=grpc&serviceName=trojan-grpc#Trojan%20Edge"

        val profile = ProxyParser.parseProxyLink(link)

        assertEquals(ProxyProtocol.TROJAN, profile.protocol)
        assertEquals("Trojan Edge", profile.remarks)
        assertEquals("example.com", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals("secret", profile.password)
        assertEquals("grpc", profile.network)
        assertEquals("tls", profile.security)
        assertEquals("edge.example.com", profile.sni)
        assertEquals("trojan-grpc", profile.serviceName)
    }

    @Test
    fun parsesShadowsocksLink() {
        val auth = Base64.encodeToString(
            "aes-256-gcm:ss-pass".toByteArray(),
            Base64.NO_WRAP or Base64.URL_SAFE,
        ).trimEnd('=')
        val link = "ss://$auth@ss.example.com:8388#SS%20Relay"

        val profile = ProxyParser.parseProxyLink(link)

        assertEquals(ProxyProtocol.SHADOWSOCKS, profile.protocol)
        assertEquals("SS Relay", profile.remarks)
        assertEquals("ss.example.com", profile.server)
        assertEquals(8388, profile.serverPort)
        assertEquals("aes-256-gcm", profile.method)
        assertEquals("ss-pass", profile.password)
    }

    @Test
    fun parsesVmessLink() {
        val payload = """
            {
              "v":"2",
              "ps":"VMess Edge",
              "add":"vmess.example.com",
              "port":"443",
              "id":"123e4567-e89b-12d3-a456-426614174000",
              "aid":"0",
              "scy":"auto",
              "net":"ws",
              "type":"none",
              "host":"cdn.example.com",
              "path":"/ws",
              "tls":"tls",
              "sni":"edge.example.com",
              "fp":"chrome"
            }
        """.trimIndent()
        val encoded = Base64.encodeToString(
            payload.toByteArray(),
            Base64.NO_WRAP or Base64.URL_SAFE,
        ).trimEnd('=')

        val profile = ProxyParser.parseProxyLink("vmess://$encoded")

        assertEquals(ProxyProtocol.VMESS, profile.protocol)
        assertEquals("VMess Edge", profile.remarks)
        assertEquals("vmess.example.com", profile.server)
        assertEquals(443, profile.serverPort)
        assertEquals("123e4567-e89b-12d3-a456-426614174000", profile.uuid)
        assertEquals("ws", profile.network)
        assertEquals("/ws", profile.path)
        assertEquals("cdn.example.com", profile.hostHeader)
        assertEquals("edge.example.com", profile.sni)
    }

    @Test
    fun parsesSocksLink() {
        val link = "socks://user:pass@socks.example.com:1080#SOCKS%20Proxy"

        val profile = ProxyParser.parseProxyLink(link)

        assertEquals(ProxyProtocol.SOCKS, profile.protocol)
        assertEquals("SOCKS Proxy", profile.remarks)
        assertEquals("socks.example.com", profile.server)
        assertEquals(1080, profile.serverPort)
        assertEquals("user", profile.username)
        assertEquals("pass", profile.password)
    }

    @Test
    fun roundTripsSupportedProtocolsThroughEncoder() {
        val profiles = listOf(
            ProxyProfile(
                protocol = ProxyProtocol.TROJAN,
                remarks = "Trojan Edge",
                server = "example.com",
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
                remarks = "SS Relay",
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
            ProxyProfile(
                protocol = ProxyProtocol.VMESS,
                remarks = "VMess Edge",
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
                path = "/ws",
                hostHeader = "cdn.example.com",
                serviceName = "",
                headerType = "none",
                rawLink = "",
            ),
            ProxyProfile(
                protocol = ProxyProtocol.SOCKS,
                remarks = "SOCKS Proxy",
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
        )

        profiles.forEach { expected ->
            val encoded = ProxyParser.encodeProxyLink(expected)
            val reparsed = ProxyParser.parseProxyLink(encoded)
            assertEquals(expected.protocol, reparsed.protocol)
            assertEquals(expected.remarks, reparsed.remarks)
            assertEquals(expected.server, reparsed.server)
            assertEquals(expected.serverPort, reparsed.serverPort)
            assertEquals(expected.password, reparsed.password)
            assertEquals(expected.username, reparsed.username)
            assertEquals(expected.method, reparsed.method)
            assertEquals(expected.network.ifBlank { "tcp" }, reparsed.network)
        }
    }

    @Test
    fun parsesBase64WrappedMixedSubscription() {
        val auth = Base64.encodeToString(
            "aes-256-gcm:ss-pass".toByteArray(),
            Base64.NO_WRAP or Base64.URL_SAFE,
        ).trimEnd('=')
        val subscriptionBody = listOf(
            "trojan://secret@example.com:443?security=tls&sni=edge.example.com#Trojan",
            "ss://$auth@ss.example.com:8388#SS",
            "socks://user:pass@socks.example.com:1080#SOCKS",
        ).joinToString("\n")
        val wrapped = Base64.encodeToString(
            subscriptionBody.toByteArray(),
            Base64.NO_WRAP,
        )

        val profiles = ProxyParser.parseSubscription(wrapped)

        assertEquals(3, profiles.size)
        assertTrue(profiles.any { it.protocol == ProxyProtocol.TROJAN })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.SHADOWSOCKS })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.SOCKS })
    }
}
