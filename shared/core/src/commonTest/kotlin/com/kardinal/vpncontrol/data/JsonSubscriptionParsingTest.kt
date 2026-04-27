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
            vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=tls&sni=edge.example.com#VLESS
            trojan://secret@example.com:443?security=tls&sni=edge.example.com#Trojan
            ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Shadowsocks
            vmess://${kotlin.io.encoding.Base64.Default.encode("""{"v":"2","ps":"VMess","add":"vmess.example.com","port":"443","id":"22222222-2222-4222-8222-222222222222","aid":"0","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"edge.example.com"}""".encodeToByteArray())}
            socks://user:pass@socks.example.com:1080#SOCKS
        """.trimIndent()
        val wrapped = kotlin.io.encoding.Base64.Default.encode(body.encodeToByteArray())

        val profiles = ProxyParser.parseSubscription(wrapped)

        assertEquals(5, profiles.size)
        assertTrue(profiles.any { it.protocol == ProxyProtocol.VLESS })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.TROJAN })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.SHADOWSOCKS })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.VMESS })
        assertTrue(profiles.any { it.protocol == ProxyProtocol.SOCKS })
    }

    @Test
    fun keepsDirectLinkListSubscriptionSupport() {
        val body = """
            vless://11111111-1111-4111-8111-111111111111@vless.example.com:443?security=tls&sni=edge.example.com#VLESS
            trojan://secret@example.com:443?security=tls&sni=edge.example.com#Trojan
            socks://user:pass@socks.example.com:1080#SOCKS
        """.trimIndent()

        val profiles = ProxyParser.parseSubscription(body)

        assertEquals(3, profiles.size)
        assertEquals(listOf(ProxyProtocol.VLESS, ProxyProtocol.TROJAN, ProxyProtocol.SOCKS), profiles.map { it.protocol })
    }

    @Test
    fun parsesSupportedJsonSubscriptionWithNonVlessProtocols() {
        val body = """
            [
              {
                "remarks": "Trojan JSON",
                "outbounds": [
                  {
                    "protocol": "trojan",
                    "tag": "proxy",
                    "settings": {
                      "servers": [
                        {
                          "address": "trojan.example.com",
                          "port": 443,
                          "password": "trojan-secret"
                        }
                      ]
                    },
                    "streamSettings": {
                      "network": "tcp",
                      "security": "tls",
                      "tlsSettings": {
                        "serverName": "edge.example.com"
                      }
                    }
                  }
                ]
              },
              {
                "remarks": "Shadowsocks JSON",
                "outbounds": [
                  {
                    "protocol": "shadowsocks",
                    "tag": "proxy",
                    "settings": {
                      "servers": [
                        {
                          "address": "ss.example.com",
                          "port": 8388,
                          "method": "aes-256-gcm",
                          "password": "ss-secret"
                        }
                      ]
                    }
                  }
                ]
              },
              {
                "remarks": "VMess JSON",
                "outbounds": [
                  {
                    "protocol": "vmess",
                    "tag": "proxy",
                    "settings": {
                      "vnext": [
                        {
                          "address": "vmess.example.com",
                          "port": 443,
                          "users": [
                            {
                              "id": "44444444-4444-4444-8444-444444444444",
                              "security": "auto"
                            }
                          ]
                        }
                      ]
                    },
                    "streamSettings": {
                      "network": "ws",
                      "security": "tls",
                      "tlsSettings": {
                        "serverName": "edge.example.com"
                      },
                      "wsSettings": {
                        "path": "/ws",
                        "headers": {
                          "Host": "cdn.example.com"
                        }
                      }
                    }
                  }
                ]
              },
              {
                "remarks": "SOCKS JSON",
                "outbounds": [
                  {
                    "protocol": "socks",
                    "tag": "proxy",
                    "settings": {
                      "servers": [
                        {
                          "address": "socks.example.com",
                          "port": 1080,
                          "users": [
                            {
                              "user": "user",
                              "pass": "pass"
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

        assertEquals(
            listOf(
                ProxyProtocol.TROJAN,
                ProxyProtocol.SHADOWSOCKS,
                ProxyProtocol.VMESS,
                ProxyProtocol.SOCKS,
            ),
            profiles.map { it.protocol },
        )
        assertEquals("Trojan JSON", profiles[0].remarks)
        assertEquals("Shadowsocks JSON", profiles[1].remarks)
        assertEquals("VMess JSON", profiles[2].remarks)
        assertEquals("SOCKS JSON", profiles[3].remarks)
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

    @Test
    fun inspectorClassifiesCommonBadSubscriptionPayloads() {
        assertEquals(
            "Subscription endpoint returned an empty response",
            SubscriptionPayloadInspector.detectPayloadError(
                body = "",
                contentType = "text/plain",
            ),
        )
        assertEquals(
            "Subscription endpoint returned an HTML page instead of a subscription payload",
            SubscriptionPayloadInspector.detectPayloadError(
                body = "<html><body>login</body></html>",
                contentType = "text/html; charset=utf-8",
            ),
        )
        assertEquals(
            "Subscription endpoint returned JSON instead of a subscription payload",
            SubscriptionPayloadInspector.detectPayloadError(
                body = """{"error":"not authorized"}""",
                contentType = null,
            ),
        )
        assertEquals(
            "Subscription endpoint returned an invalid subscription payload",
            SubscriptionPayloadInspector.invalidPayloadMessage(
                IllegalArgumentException("Subscription format is not recognized as a supported proxy link list"),
            ),
        )
    }
}
