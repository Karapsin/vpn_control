package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

internal object JsonSubscriptionParser {
    fun parse(rawBody: String): List<ProxyProfile>? {
        val trimmed = rawBody.trim()
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return null
        }
        val root = runCatching { CompactJson.parseToJsonElement(trimmed) }.getOrNull() ?: return null
        val configs = root.subscriptionConfigObjects().takeIf { it.isNotEmpty() } ?: return null
        val profiles = buildList {
            configs.forEachIndexed { index, config ->
                addAll(parseConfigProfiles(config, index))
            }
        }.distinctBy { it.rawLink }
        return profiles.takeIf { it.isNotEmpty() }
    }

    private fun JsonElement.subscriptionConfigObjects(): List<JsonObject> {
        return when (this) {
            is JsonObject -> listOf(this)
            is JsonArray -> mapNotNull { it as? JsonObject }
            else -> emptyList()
        }
    }

    private fun parseConfigProfiles(
        config: JsonObject,
        index: Int,
    ): List<ProxyProfile> {
        val remarks = config.string("remarks")
        val outbounds = config.objectArray("outbounds")
        val supported = outbounds.filter { outbound ->
            outbound.string("protocol").lowercase() in supportedJsonProtocols
        }
        if (supported.isEmpty()) {
            return emptyList()
        }
        val preferred = supported.filter { outbound ->
            outbound.string("tag").equals("proxy", ignoreCase = true)
        }
        val chosen = if (preferred.isNotEmpty()) preferred else supported.take(1)
        return chosen.mapNotNull { outbound ->
            runCatching {
                parseOutbound(
                    outbound = outbound,
                    fallbackRemarks = remarks,
                    configIndex = index,
                )
            }.getOrNull()
        }
    }

    private fun parseOutbound(
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        return when (outbound.string("protocol").lowercase()) {
            "vless" -> parseVnextOutbound(
                protocol = ProxyProtocol.VLESS,
                outbound = outbound,
                fallbackRemarks = fallbackRemarks,
                configIndex = configIndex,
            )
            "vmess" -> parseVnextOutbound(
                protocol = ProxyProtocol.VMESS,
                outbound = outbound,
                fallbackRemarks = fallbackRemarks,
                configIndex = configIndex,
            )
            "trojan" -> parseTrojanOutbound(outbound, fallbackRemarks, configIndex)
            "shadowsocks" -> parseShadowsocksOutbound(outbound, fallbackRemarks, configIndex)
            "socks" -> parseSocksOutbound(outbound, fallbackRemarks, configIndex)
            else -> error("Unsupported JSON outbound protocol")
        }
    }

    private fun parseVnextOutbound(
        protocol: ProxyProtocol,
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        val server = outbound.objectAt("settings")
            .objectArray("vnext")
            .firstOrNull()
            ?: error("Missing vnext server entry")
        val user = server.objectArray("users").firstOrNull()
            ?: error("Missing vnext user entry")
        val stream = outbound.objectAt("streamSettings")
        val transport = stream.transportSettings()
        val host = server.string("address").ifBlank { error("Missing outbound host") }
        val port = server.int("port").takeIf { it > 0 } ?: 443
        val remarks = fallbackRemarks.ifBlank {
            outbound.string("tag").ifBlank { "${protocol.name.lowercase()}-$configIndex" }
        }
        val security = normalizeSecurity(stream.string("security"))
        val reality = stream.objectAt("realitySettings")
        val tls = stream.objectAt("tlsSettings")
        val tlsServerName = reality.string("serverName")
            .ifBlank { tls.string("serverName") }
            .ifBlank { host }
        val profile = ProxyProfile(
            protocol = protocol,
            remarks = remarks,
            server = host,
            serverPort = port,
            uuid = user.string("id").trim(),
            username = "",
            password = "",
            method = "",
            network = stream.string("network").ifBlank { "tcp" },
            flow = user.string("flow"),
            security = security,
            sni = if (security.isBlank()) "" else tlsServerName,
            fingerprint = reality.string("fingerprint")
                .ifBlank { tls.string("fingerprint") }
                .ifBlank { "chrome" },
            publicKey = reality.string("publicKey"),
            shortId = reality.string("shortId"),
            path = transport.path,
            hostHeader = transport.hostHeader,
            serviceName = transport.serviceName,
            headerType = transport.headerType,
            alterId = user.int("alterId"),
            vmessSecurity = user.string("security").ifBlank { "auto" },
            rawLink = "",
        )
        require(profile.uuid.isNotBlank()) { "Missing ${protocol.name} UUID" }
        return profile.copy(rawLink = ProxyLinkEncoder.encodeProxyLink(profile))
    }

    private fun parseTrojanOutbound(
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        val server = outbound.objectAt("settings")
            .objectArray("servers")
            .firstOrNull()
            ?: error("Missing Trojan server entry")
        val stream = outbound.objectAt("streamSettings")
        val transport = stream.transportSettings()
        val host = server.string("address").ifBlank { error("Missing Trojan host") }
        val port = server.int("port").takeIf { it > 0 } ?: 443
        val security = normalizeSecurity(stream.string("security").ifBlank { "tls" })
        val reality = stream.objectAt("realitySettings")
        val tls = stream.objectAt("tlsSettings")
        val profile = ProxyProfile(
            protocol = ProxyProtocol.TROJAN,
            remarks = fallbackRemarks.ifBlank {
                outbound.string("tag").ifBlank { "trojan-$configIndex" }
            },
            server = host,
            serverPort = port,
            username = "",
            password = server.string("password"),
            network = stream.string("network").ifBlank { "tcp" },
            flow = "",
            security = security,
            sni = if (security.isBlank()) "" else reality.string("serverName")
                .ifBlank { tls.string("serverName") }
                .ifBlank { host },
            fingerprint = reality.string("fingerprint")
                .ifBlank { tls.string("fingerprint") }
                .ifBlank { "chrome" },
            publicKey = reality.string("publicKey"),
            shortId = reality.string("shortId"),
            path = transport.path,
            hostHeader = transport.hostHeader,
            serviceName = transport.serviceName,
            headerType = transport.headerType,
            rawLink = "",
        )
        require(profile.password.isNotBlank()) { "Missing Trojan password" }
        return profile.copy(rawLink = ProxyLinkEncoder.encodeProxyLink(profile))
    }

    private fun parseShadowsocksOutbound(
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        val server = outbound.objectAt("settings")
            .objectArray("servers")
            .firstOrNull()
            ?: error("Missing Shadowsocks server entry")
        val profile = ProxyProfile(
            protocol = ProxyProtocol.SHADOWSOCKS,
            remarks = fallbackRemarks.ifBlank {
                outbound.string("tag").ifBlank { "shadowsocks-$configIndex" }
            },
            server = server.string("address").ifBlank { error("Missing Shadowsocks host") },
            serverPort = server.int("port").takeIf { it > 0 } ?: 443,
            username = "",
            password = server.string("password"),
            method = server.string("method"),
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
        require(profile.password.isNotBlank()) { "Missing Shadowsocks password" }
        require(profile.method.isNotBlank()) { "Missing Shadowsocks method" }
        return profile.copy(rawLink = ProxyLinkEncoder.encodeProxyLink(profile))
    }

    private fun parseSocksOutbound(
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        val server = outbound.objectAt("settings")
            .objectArray("servers")
            .firstOrNull()
            ?: error("Missing SOCKS server entry")
        val user = server.objectArray("users").firstOrNull()
        val profile = ProxyProfile(
            protocol = ProxyProtocol.SOCKS,
            remarks = fallbackRemarks.ifBlank {
                outbound.string("tag").ifBlank { "socks-$configIndex" }
            },
            server = server.string("address").ifBlank { error("Missing SOCKS host") },
            serverPort = server.int("port").takeIf { it > 0 } ?: 1080,
            username = user?.string("user").orEmpty(),
            password = user?.string("pass").orEmpty(),
            method = "",
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
        return profile.copy(rawLink = ProxyLinkEncoder.encodeProxyLink(profile))
    }

    private fun JsonObject.transportSettings(): JsonTransportSettings {
        val network = string("network").ifBlank { "tcp" }
        return when (network) {
            "grpc" -> JsonTransportSettings(
                path = "",
                hostHeader = "",
                serviceName = objectAt("grpcSettings").string("serviceName"),
                headerType = "none",
            )
            "ws" -> JsonTransportSettings(
                path = objectAt("wsSettings").string("path"),
                hostHeader = objectAt("wsSettings").objectAt("headers").string("Host"),
                serviceName = "",
                headerType = "none",
            )
            "httpupgrade" -> JsonTransportSettings(
                path = objectAt("httpupgradeSettings").string("path"),
                hostHeader = objectAt("httpupgradeSettings").string("host"),
                serviceName = "",
                headerType = "none",
            )
            else -> JsonTransportSettings(
                path = "",
                hostHeader = "",
                serviceName = "",
                headerType = objectAt("tcpSettings").objectAt("header").string("type").ifBlank { "none" },
            )
        }
    }

    private fun normalizeSecurity(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.equals("none", ignoreCase = true)) "" else trimmed
    }

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
    }

    private fun JsonObject.objectAt(key: String): JsonObject {
        return this[key] as? JsonObject ?: JsonObject(emptyMap())
    }

    private fun JsonObject.objectArray(key: String): List<JsonObject> {
        return (this[key] as? JsonArray)
            ?.mapNotNull { it as? JsonObject }
            .orEmpty()
    }

    private fun JsonObject.int(key: String): Int {
        return string(key).toIntOrNull() ?: 0
    }

    private data class JsonTransportSettings(
        val path: String,
        val hostHeader: String,
        val serviceName: String,
        val headerType: String,
    )
}

private val supportedJsonProtocols = setOf("vless", "trojan", "shadowsocks", "vmess", "socks")
