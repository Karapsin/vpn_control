package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
class JsonSubscriptionParsingTest {
    @Test
    fun parsesSupportedJsonSubscriptionArrayAndIgnoresAuxiliaryOutbounds() {
        val body = """
            [
              {
                "remarks": "Netherlands",
                "outbounds": [
                  {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                      "vnext": [
                        {
                          "address": "nl.example.net",
                          "port": 8443,
                          "users": [
                            {
                              "id": "11111111-1111-1111-1111-111111111111",
                              "encryption": "none",
                              "flow": "xtls-rprx-vision"
                            }
                          ]
                        }
                      ]
                    },
                    "streamSettings": {
                      "network": "tcp",
                      "security": "reality",
                      "realitySettings": {
                        "serverName": "sni.nl.example.net",
                        "fingerprint": "chrome",
                        "publicKey": "pubkey-1",
                        "shortId": "abcd1234"
                      },
                      "tcpSettings": {
                        "header": {
                          "type": "none"
                        }
                      }
                    }
                  },
                  {
                    "protocol": "freedom",
                    "tag": "direct"
                  },
                  {
                    "protocol": "blackhole",
                    "tag": "block"
                  }
                ]
              },
              {
                "remarks": "Netherlands bypass",
                "outbounds": [
                  {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                      "vnext": [
                        {
                          "address": "nl-bypass.example.net",
                          "port": 443,
                          "users": [
                            {
                              "id": "22222222-2222-2222-2222-222222222222",
                              "encryption": "none"
                            }
                          ]
                        }
                      ]
                    },
                    "streamSettings": {
                      "network": "ws",
                      "security": "tls",
                      "tlsSettings": {
                        "serverName": "edge.example.net",
                        "fingerprint": "firefox"
                      },
                      "wsSettings": {
                        "path": "/ws",
                        "headers": {
                          "Host": "cdn.example.net"
                        }
                      }
                    }
                  },
                  {
                    "protocol": "socks",
                    "tag": "ru-upstream",
                    "settings": {
                      "servers": [
                        {
                          "address": "127.0.0.1",
                          "port": 1080,
                          "users": [
                            {
                              "user": "aux",
                              "pass": "aux-pass"
                            }
                          ]
                        }
                      ]
                    }
                  }
                ]
              }
            ]
        """.trimIndent()

        val profiles = ProxyParser.parseSubscription(body)

        assertEquals(2, profiles.size)

        val first = profiles[0]
        assertEquals(ProxyProtocol.VLESS, first.protocol)
        assertEquals("Netherlands", first.remarks)
        assertEquals("nl.example.net", first.server)
        assertEquals(8443, first.serverPort)
        assertEquals("11111111-1111-1111-1111-111111111111", first.uuid)
        assertEquals("reality", first.security)
        assertEquals("sni.nl.example.net", first.sni)
        assertEquals("pubkey-1", first.publicKey)
        assertEquals("abcd1234", first.shortId)
        assertTrue(first.rawLink.startsWith("vless://"))

        val second = profiles[1]
        assertEquals(ProxyProtocol.VLESS, second.protocol)
        assertEquals("Netherlands bypass", second.remarks)
        assertEquals("nl-bypass.example.net", second.server)
        assertEquals("ws", second.network)
        assertEquals("tls", second.security)
        assertEquals("edge.example.net", second.sni)
        assertEquals("/ws", second.path)
        assertEquals("cdn.example.net", second.hostHeader)
    }

    @Test
    fun keepsBase64LinkListSubscriptionSupport() {
        val body = """
            trojan://secret@example.com:443?security=tls&sni=edge.example.com#Trojan
            socks://user:pass@socks.example.com:1080#SOCKS
        """.trimIndent()
        val wrapped = kotlin.io.encoding.Base64.Default.encode(body.encodeToByteArray())

        val profiles = ProxyParser.parseSubscription(wrapped)

        assertEquals(2, profiles.size)
        assertTrue(profiles.any { it.protocol == ProxyProtocol.TROJAN })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.SOCKS })
    }

    @Test
    fun inspectorAllowsSupportedJsonButRejectsUnknownJson() {
        val supportedJson = """
            [
              {
                "remarks": "Netherlands",
                "outbounds": [
                  {
                    "protocol": "vless",
                    "tag": "proxy",
                    "settings": {
                      "vnext": [
                        {
                          "address": "nl.example.net",
                          "port": 443,
                          "users": [
                            {
                              "id": "33333333-3333-3333-3333-333333333333"
                            }
                          ]
                        }
                      ]
                    }
                  }
                ]
              }
            ]
        """.trimIndent()

        assertNull(
            SubscriptionPayloadInspector.detectPayloadError(
                body = supportedJson,
                contentType = "application/json",
            ),
        )

        assertEquals(
            "Subscription endpoint returned JSON instead of a subscription payload",
            SubscriptionPayloadInspector.detectPayloadError(
                body = """{"hello":"world"}""",
                contentType = "application/json",
            ),
        )
    }
}
