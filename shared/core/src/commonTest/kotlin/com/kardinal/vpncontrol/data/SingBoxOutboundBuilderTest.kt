package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class SingBoxOutboundBuilderTest {
    @Test
    fun vlessRealityWebsocketIncludesTlsTransportAndNetwork() {
        val outbound = SingBoxOutboundBuilder.buildOutbound(
            profile = profile(
                protocol = ProxyProtocol.VLESS,
                uuid = "00000000-0000-0000-0000-000000000001",
                network = "ws",
                flow = "xtls-rprx-vision",
                security = "reality",
                sni = "edge.example.com",
                fingerprint = "firefox",
                publicKey = "public-key",
                shortId = "short-id",
                path = "/ws",
                hostHeader = "host.example.com",
            ),
        )

        assertEquals("vless", outbound.string("type"))
        assertEquals("proxy", outbound.string("tag"))
        assertEquals("example.com", outbound.string("server"))
        assertEquals(443, outbound.int("server_port"))
        assertEquals("00000000-0000-0000-0000-000000000001", outbound.string("uuid"))
        assertEquals("xudp", outbound.string("packet_encoding"))
        assertEquals("xtls-rprx-vision", outbound.string("flow"))
        assertEquals("ws", outbound.string("network"))

        val tls = outbound.objectValue("tls")
        assertTrue(tls.boolean("enabled"))
        assertEquals("edge.example.com", tls.string("server_name"))
        assertEquals("firefox", tls.objectValue("utls").string("fingerprint"))
        assertEquals("public-key", tls.objectValue("reality").string("public_key"))
        assertEquals("short-id", tls.objectValue("reality").string("short_id"))

        val transport = outbound.objectValue("transport")
        assertEquals("ws", transport.string("type"))
        assertEquals("/ws", transport.string("path"))
        assertEquals("host.example.com", transport.objectValue("headers").string("Host"))
    }

    @Test
    fun trojanGrpcEnablesTlsAndTransport() {
        val outbound = SingBoxOutboundBuilder.buildOutbound(
            profile = profile(
                protocol = ProxyProtocol.TROJAN,
                password = "secret",
                network = "grpc",
                serviceName = "grpc-service",
            ),
        )

        assertEquals("trojan", outbound.string("type"))
        assertEquals("secret", outbound.string("password"))
        assertEquals("grpc", outbound.string("network"))
        assertEquals("example.com", outbound.objectValue("tls").string("server_name"))
        assertEquals("grpc", outbound.objectValue("transport").string("type"))
        assertEquals("grpc-service", outbound.objectValue("transport").string("service_name"))
    }

    @Test
    fun shadowsocksUdpKeepsNetworkWithoutTlsOrTransport() {
        val outbound = SingBoxOutboundBuilder.buildOutbound(
            profile = profile(
                protocol = ProxyProtocol.SHADOWSOCKS,
                method = "2022-blake3-aes-128-gcm",
                password = "secret",
                network = "udp",
            ),
        )

        assertEquals("shadowsocks", outbound.string("type"))
        assertEquals("2022-blake3-aes-128-gcm", outbound.string("method"))
        assertEquals("secret", outbound.string("password"))
        assertEquals("udp", outbound.string("network"))
        assertFalse("tls" in outbound)
        assertFalse("transport" in outbound)
    }

    @Test
    fun socksPreservesCredentialsWithoutTlsOrNetwork() {
        val outbound = SingBoxOutboundBuilder.buildOutbound(
            profile = profile(
                protocol = ProxyProtocol.SOCKS,
                username = "user",
                password = "secret",
                network = "tcp",
            ),
        )

        assertEquals("socks", outbound.string("type"))
        assertEquals("5", outbound.string("version"))
        assertEquals("user", outbound.string("username"))
        assertEquals("secret", outbound.string("password"))
        assertFalse("network" in outbound)
        assertFalse("tls" in outbound)
        assertFalse("transport" in outbound)
    }

    @Test
    fun vmessUsesAutoSecurityAndTlsWhenRequested() {
        val outbound = SingBoxOutboundBuilder.buildOutbound(
            profile = profile(
                protocol = ProxyProtocol.VMESS,
                uuid = "00000000-0000-0000-0000-000000000002",
                network = "tcp",
                security = "tls",
                alterId = 2,
                vmessSecurity = "",
            ),
        )

        assertEquals("vmess", outbound.string("type"))
        assertEquals("auto", outbound.string("security"))
        assertEquals(2, outbound.int("alter_id"))
        assertEquals("tcp", outbound.string("network"))
        assertTrue(outbound.objectValue("tls").boolean("enabled"))
    }

    @Test
    fun customProfileUsesProvidedErrorMessage() {
        val error = assertFailsWith<IllegalStateException> {
            SingBoxOutboundBuilder.buildOutbound(
                profile = profile(protocol = ProxyProtocol.CUSTOM),
                customConfigErrorMessage = "desktop custom unsupported",
            )
        }

        assertEquals("desktop custom unsupported", error.message)
    }

    private fun profile(
        protocol: ProxyProtocol,
        uuid: String = "",
        username: String = "",
        password: String = "",
        method: String = "",
        network: String = "tcp",
        flow: String = "",
        security: String = "",
        sni: String = "",
        fingerprint: String = "",
        publicKey: String = "",
        shortId: String = "",
        path: String = "",
        hostHeader: String = "",
        serviceName: String = "",
        alterId: Int = 0,
        vmessSecurity: String = "auto",
    ): ProxyProfile {
        return ProxyProfile(
            protocol = protocol,
            remarks = "Example",
            server = "example.com",
            serverPort = 443,
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
            headerType = "",
            alterId = alterId,
            vmessSecurity = vmessSecurity,
            rawLink = "proxy://example",
        )
    }
}

private fun kotlinx.serialization.json.JsonObject.string(key: String): String {
    return this[key]!!.jsonPrimitive.content
}

private fun kotlinx.serialization.json.JsonObject.int(key: String): Int {
    return this[key]!!.jsonPrimitive.int
}

private fun kotlinx.serialization.json.JsonObject.boolean(key: String): Boolean {
    return this[key]!!.jsonPrimitive.boolean
}

private fun kotlinx.serialization.json.JsonObject.objectValue(key: String): kotlinx.serialization.json.JsonObject {
    return this[key]!!.jsonObject
}
