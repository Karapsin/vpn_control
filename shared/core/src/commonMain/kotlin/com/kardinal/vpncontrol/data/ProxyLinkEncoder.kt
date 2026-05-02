package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

internal object ProxyLinkEncoder {
    fun encodeProxyLink(profile: ProxyProfile): String {
        return when (profile.protocol) {
            ProxyProtocol.VLESS -> encodeVlessLink(profile)
            ProxyProtocol.TROJAN -> encodeTrojanLink(profile)
            ProxyProtocol.SHADOWSOCKS -> encodeShadowsocksLink(profile)
            ProxyProtocol.VMESS -> encodeVmessLink(profile)
            ProxyProtocol.SOCKS -> encodeSocksLink(profile)
            ProxyProtocol.CUSTOM -> error("Custom configs do not have a proxy link representation")
        }
    }

    fun encodeVlessLink(profile: ProxyProfile): String {
        val query = buildList {
            add("type" to profile.network.ifBlank { "tcp" })
            profile.security.takeIf { it.isNotBlank() }?.let { add("security" to it) }
            profile.flow.takeIf { it.isNotBlank() }?.let { add("flow" to it) }
            profile.sni.takeIf { it.isNotBlank() }?.let { add("sni" to it) }
            profile.fingerprint.takeIf { it.isNotBlank() && it != "chrome" }?.let { add("fp" to it) }
            profile.publicKey.takeIf { it.isNotBlank() }?.let { add("pbk" to it) }
            profile.shortId.takeIf { it.isNotBlank() }?.let { add("sid" to it) }
            profile.path.takeIf { it.isNotBlank() }?.let { add("path" to it) }
            profile.hostHeader.takeIf { it.isNotBlank() }?.let { add("host" to it) }
            profile.serviceName.takeIf { it.isNotBlank() }?.let { add("serviceName" to it) }
            profile.headerType.takeIf { it.isNotBlank() && it != "none" }?.let { add("headerType" to it) }
        }.joinToString("&") { (key, value) ->
            "${key.encodeUrlComponent()}=${value.encodeUrlComponent()}"
        }

        val fragment = profile.remarks.takeIf { it.isNotBlank() }?.encodeUrlComponent().orEmpty()
        return buildString {
            append("vless://")
            append(profile.uuid.encodeUrlComponent())
            append('@')
            append(formatHost(profile.server))
            append(':')
            append(profile.serverPort)
            if (query.isNotBlank()) {
                append('?')
                append(query)
            }
            if (fragment.isNotBlank()) {
                append('#')
                append(fragment)
            }
        }
    }

    private fun encodeTrojanLink(profile: ProxyProfile): String {
        val query = buildList {
            profile.security.takeIf { it.isNotBlank() }?.let { add("security" to it) }
            profile.sni.takeIf { it.isNotBlank() }?.let { add("sni" to it) }
            profile.fingerprint.takeIf { it.isNotBlank() && it != "chrome" }?.let { add("fp" to it) }
            add("type" to profile.network.ifBlank { "tcp" })
            profile.path.takeIf { it.isNotBlank() }?.let { add("path" to it) }
            profile.hostHeader.takeIf { it.isNotBlank() }?.let { add("host" to it) }
            profile.serviceName.takeIf { it.isNotBlank() }?.let { add("serviceName" to it) }
            profile.headerType.takeIf { it.isNotBlank() && it != "none" }?.let { add("headerType" to it) }
        }.joinToString("&") { (key, value) ->
            "${key.encodeUrlComponent()}=${value.encodeUrlComponent()}"
        }
        return buildString {
            append("trojan://")
            append(profile.password.encodeUrlComponent())
            append('@')
            append(formatHost(profile.server))
            append(':')
            append(profile.serverPort)
            if (query.isNotBlank()) {
                append('?')
                append(query)
            }
            profile.remarks.takeIf { it.isNotBlank() }?.let {
                append('#')
                append(it.encodeUrlComponent())
            }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encodeShadowsocksLink(profile: ProxyProfile): String {
        val userInfo = "${profile.method}:${profile.password}"
        val encodedUserInfo = Base64.UrlSafe.encode(userInfo.encodeToByteArray()).trimEnd('=')
        return buildString {
            append("ss://")
            append(encodedUserInfo)
            append('@')
            append(formatHost(profile.server))
            append(':')
            append(profile.serverPort)
            if (profile.plugin.isNotBlank()) {
                append("?plugin=")
                append(profile.plugin.encodeUrlComponent())
            }
            profile.remarks.takeIf { it.isNotBlank() }?.let {
                append('#')
                append(it.encodeUrlComponent())
            }
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun encodeVmessLink(profile: ProxyProfile): String {
        val payload = buildJsonObject {
            put("v", JsonPrimitive("2"))
            put("ps", JsonPrimitive(profile.remarks))
            put("add", JsonPrimitive(profile.server))
            put("port", JsonPrimitive(profile.serverPort.toString()))
            put("id", JsonPrimitive(profile.uuid))
            put("aid", JsonPrimitive(profile.alterId.toString()))
            put("scy", JsonPrimitive(profile.vmessSecurity.ifBlank { "auto" }))
            put("net", JsonPrimitive(profile.network.ifBlank { "tcp" }))
            put("type", JsonPrimitive(profile.headerType.ifBlank { "none" }))
            put("host", JsonPrimitive(profile.hostHeader))
            put("path", JsonPrimitive(if (profile.network == "grpc") profile.serviceName else profile.path))
            put("tls", JsonPrimitive(if (profile.security.isNotBlank()) "tls" else ""))
            put("sni", JsonPrimitive(profile.sni))
            put("fp", JsonPrimitive(profile.fingerprint))
        }
        val encoded = Base64.UrlSafe.encode(
            CompactJson.encodeToString(
                JsonObject.serializer(),
                payload,
            ).encodeToByteArray(),
        ).trimEnd('=')
        return "vmess://$encoded"
    }

    private fun encodeSocksLink(profile: ProxyProfile): String {
        return buildString {
            append("socks://")
            if (profile.username.isNotBlank()) {
                append(profile.username.encodeUrlComponent())
                if (profile.password.isNotBlank()) {
                    append(':')
                    append(profile.password.encodeUrlComponent())
                }
                append('@')
            }
            append(formatHost(profile.server))
            append(':')
            append(profile.serverPort)
            profile.remarks.takeIf { it.isNotBlank() }?.let {
                append('#')
                append(it.encodeUrlComponent())
            }
        }
    }

    private fun formatHost(host: String): String {
        return if (host.contains(':') && !host.startsWith("[") && !host.endsWith("]")) {
            "[$host]"
        } else {
            host
        }
    }
}
