package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalEncodingApi::class)
class SubscriptionPayloadParserTest {
    @Test
    fun parsesBase64WrappedDirectLinkList() {
        val body = """
            trojan://secret@example.com:443?security=tls&sni=edge.example.com#Trojan
            socks://user:pass@socks.example.com:1080#SOCKS
        """.trimIndent()
        val wrapped = Base64.Default.encode(body.encodeToByteArray())

        val profiles = ProxyParser.parseSubscription(wrapped)

        assertEquals(listOf(ProxyProtocol.TROJAN, ProxyProtocol.SOCKS), profiles.map { it.protocol })
    }

    @Test
    fun parsesBase64WrappedJsonBeforeDirectLinkFallback() {
        val body = """
            [
              {
                "remarks": "JSON Trojan",
                "outbounds": [
                  {
                    "protocol": "trojan",
                    "tag": "proxy",
                    "settings": {
                      "servers": [
                        {
                          "address": "json-trojan.example.com",
                          "port": 443,
                          "password": "secret"
                        }
                      ]
                    },
                    "streamSettings": {
                      "network": "tcp",
                      "security": "tls"
                    }
                  }
                ]
              }
            ]
        """.trimIndent()
        val wrapped = Base64.Default.encode(body.encodeToByteArray())

        val profiles = ProxyParser.parseSubscription(wrapped)

        assertEquals(1, profiles.size)
        assertEquals(ProxyProtocol.TROJAN, profiles.single().protocol)
        assertEquals("JSON Trojan", profiles.single().remarks)
        assertEquals("json-trojan.example.com", profiles.single().server)
    }

    @Test
    fun rejectsInvalidSubscriptionPayload() {
        val error = assertFailsWith<IllegalStateException> {
            ProxyParser.parseSubscription("this is not a supported subscription")
        }

        assertEquals(
            "Subscription format is not recognized as a supported proxy link list",
            error.message,
        )
    }
}
