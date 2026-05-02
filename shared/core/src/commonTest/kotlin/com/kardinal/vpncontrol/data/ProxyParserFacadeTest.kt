package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlin.test.Test
import kotlin.test.assertEquals

class ProxyParserFacadeTest {
    @Test
    fun vlessCompatibilityFacadeMatchesProxyParser() {
        val link = "vless://11111111-1111-1111-1111-111111111111@example.com:8443?type=tcp&security=reality&sni=sni.example.com&fp=chrome&pbk=pubkey&sid=abcd#Example"

        val proxyProfile = ProxyParser.parseVlessLink(link)
        val vlessProfile = VlessParser.parseVlessLink(link)

        assertEquals(proxyProfile, vlessProfile)
        assertEquals(ProxyParser.encodeVlessLink(proxyProfile), VlessParser.encodeVlessLink(vlessProfile))
    }

    @Test
    fun roundTripsDirectLinkProtocolsThroughFacade() {
        val profiles = listOf(
            proxyProfile(
                protocol = ProxyProtocol.VLESS,
                remarks = "VLESS Edge",
                server = "vless.example.com",
                serverPort = 8443,
                uuid = "11111111-1111-1111-1111-111111111111",
                network = "tcp",
                security = "reality",
                sni = "sni.example.com",
                fingerprint = "chrome",
                publicKey = "pubkey",
                shortId = "abcd",
            ),
            proxyProfile(
                protocol = ProxyProtocol.TROJAN,
                remarks = "Trojan Edge",
                server = "trojan.example.com",
                serverPort = 443,
                password = "secret",
                network = "grpc",
                security = "tls",
                sni = "edge.example.com",
                fingerprint = "chrome",
                serviceName = "trojan-grpc",
            ),
            proxyProfile(
                protocol = ProxyProtocol.SHADOWSOCKS,
                remarks = "SS Relay",
                server = "ss.example.com",
                serverPort = 8388,
                password = "ss-pass",
                method = "aes-256-gcm",
                network = "tcp",
                fingerprint = "chrome",
            ),
            proxyProfile(
                protocol = ProxyProtocol.VMESS,
                remarks = "VMess Edge",
                server = "vmess.example.com",
                serverPort = 443,
                uuid = "123e4567-e89b-12d3-a456-426614174000",
                network = "ws",
                security = "tls",
                sni = "edge.example.com",
                fingerprint = "chrome",
                path = "/ws",
                hostHeader = "cdn.example.com",
            ),
            proxyProfile(
                protocol = ProxyProtocol.SOCKS,
                remarks = "SOCKS Proxy",
                server = "socks.example.com",
                serverPort = 1080,
                username = "user",
                password = "pass",
                network = "tcp",
                fingerprint = "chrome",
            ),
        )

        profiles.forEach { expected ->
            val reparsed = ProxyParser.parseProxyLink(ProxyParser.encodeProxyLink(expected))

            assertEquals(expected.protocol, reparsed.protocol)
            assertEquals(expected.remarks, reparsed.remarks)
            assertEquals(expected.server, reparsed.server)
            assertEquals(expected.serverPort, reparsed.serverPort)
            assertEquals(expected.uuid, reparsed.uuid)
            assertEquals(expected.username, reparsed.username)
            assertEquals(expected.password, reparsed.password)
            assertEquals(expected.method, reparsed.method)
            assertEquals(expected.network, reparsed.network)
        }
    }

    private fun proxyProfile(
        protocol: ProxyProtocol,
        remarks: String,
        server: String,
        serverPort: Int,
        uuid: String = "",
        username: String = "",
        password: String = "",
        method: String = "",
        network: String = "tcp",
        flow: String = "",
        security: String = "",
        sni: String = "",
        fingerprint: String = "chrome",
        publicKey: String = "",
        shortId: String = "",
        path: String = "",
        hostHeader: String = "",
        serviceName: String = "",
        headerType: String = "none",
    ): ProxyProfile {
        return ProxyProfile(
            protocol = protocol,
            remarks = remarks,
            server = server,
            serverPort = serverPort,
            uuid = uuid,
            username = username,
            password = password,
            method = method,
            network = network,
            flow = flow,
            security = security,
            sni = sni,
            fingerprint = fingerprint,
            publicKey = publicKey,
            shortId = shortId,
            path = path,
            hostHeader = hostHeader,
            serviceName = serviceName,
            headerType = headerType,
            rawLink = "",
        )
    }
}
