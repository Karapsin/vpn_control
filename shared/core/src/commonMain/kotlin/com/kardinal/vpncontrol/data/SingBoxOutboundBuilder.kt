package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

object SingBoxOutboundBuilder {
    fun buildOutbound(
        profile: ProxyProfile,
        tag: String = "proxy",
        domainResolverTag: String? = null,
        customConfigErrorMessage: String = "Custom configs must be used as direct runtime JSON",
    ): JsonObject {
        val base = when (profile.protocol) {
            ProxyProtocol.VLESS -> buildJsonObject {
                put("type", "vless")
                put("tag", tag)
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuid)
                put("packet_encoding", "xudp")
                if (profile.flow.isNotBlank()) {
                    put("flow", profile.flow)
                }
            }
            ProxyProtocol.TROJAN -> buildJsonObject {
                put("type", "trojan")
                put("tag", tag)
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("password", profile.password)
            }
            ProxyProtocol.SHADOWSOCKS -> buildJsonObject {
                put("type", "shadowsocks")
                put("tag", tag)
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("method", profile.method)
                put("password", profile.password)
            }
            ProxyProtocol.VMESS -> buildJsonObject {
                put("type", "vmess")
                put("tag", tag)
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuid)
                put("security", profile.vmessSecurity.ifBlank { "auto" })
                put("alter_id", profile.alterId)
                put("packet_encoding", "xudp")
            }
            ProxyProtocol.SOCKS -> buildJsonObject {
                put("type", "socks")
                put("tag", tag)
                put("server", profile.server)
                put("server_port", profile.serverPort)
                put("version", "5")
                if (profile.username.isNotBlank()) {
                    put("username", profile.username)
                }
                if (profile.password.isNotBlank()) {
                    put("password", profile.password)
                }
            }
            ProxyProtocol.CUSTOM -> error(customConfigErrorMessage)
        }

        return buildJsonObject {
            base.forEach { (key, value) -> put(key, value) }
            // For VLESS/VMess/Trojan, ProxyProfile.network is a stream transport
            // name. sing-box's outbound.network is a TCP/UDP capability filter.
            if (profile.protocol == ProxyProtocol.SHADOWSOCKS &&
                profile.network.isNotBlank() &&
                profile.network != "tcp"
            ) {
                put("network", profile.network)
            }
            buildTls(profile)?.let { put("tls", it) }
            buildTransport(profile)?.let { put("transport", it) }
            domainResolverTag?.takeIf(String::isNotBlank)?.let { put("domain_resolver", it) }
        }
    }

    private fun buildTls(profile: ProxyProfile): JsonObject? {
        val shouldEnable = when (profile.protocol) {
            ProxyProtocol.VLESS -> profile.security.isNotBlank()
            ProxyProtocol.TROJAN -> true
            ProxyProtocol.VMESS -> profile.security.isNotBlank()
            ProxyProtocol.SHADOWSOCKS, ProxyProtocol.SOCKS, ProxyProtocol.CUSTOM -> false
        }
        if (!shouldEnable) return null

        return buildJsonObject {
            put("enabled", true)
            put("server_name", profile.sni.ifBlank { profile.server })
            put(
                "utls",
                buildJsonObject {
                    put("enabled", true)
                    put("fingerprint", profile.fingerprint.ifBlank { "chrome" })
                },
            )
            if (profile.protocol == ProxyProtocol.VLESS && profile.security == "reality") {
                put(
                    "reality",
                    buildJsonObject {
                        put("enabled", true)
                        put("public_key", profile.publicKey)
                        put("short_id", profile.shortId)
                    },
                )
            }
        }
    }

    private fun buildTransport(profile: ProxyProfile): JsonObject? {
        return when (profile.network) {
            "ws" -> buildJsonObject {
                put("type", "ws")
                if (profile.path.isNotBlank()) {
                    put("path", profile.path)
                }
                if (profile.hostHeader.isNotBlank()) {
                    put(
                        "headers",
                        buildJsonObject {
                            put("Host", profile.hostHeader)
                        },
                    )
                }
            }
            "grpc" -> buildJsonObject {
                put("type", "grpc")
                if (profile.serviceName.isNotBlank()) {
                    put("service_name", profile.serviceName)
                }
            }
            else -> null
        }
    }
}
