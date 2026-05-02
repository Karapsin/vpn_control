package com.kardinal.vpncontrol.data

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
}
