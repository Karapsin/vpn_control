package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.VlessProfile
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object ProxyParser {
    fun parseSubscription(rawBody: String): List<ProxyProfile> {
        parseJsonSubscription(rawBody)?.let { return it }

        val directLines = rawBody.lines().map { it.trim() }.filter { it.isNotBlank() }
        val lines = if (directLines.any(::looksLikeSupportedLink)) {
            directLines
        } else {
            decodeLooseBase64(rawBody.encodeToByteArray())
                .lines()
                .map { it.trim() }
                .filter { it.isNotBlank() }
        }

        val profiles = lines.mapNotNull { line ->
            runCatching { parseProxyLink(line) }.getOrNull()
        }
        require(profiles.isNotEmpty()) {
            "Subscription format is not recognized as a supported proxy link list"
        }
        return profiles
    }

    internal fun supportsJsonSubscription(rawBody: String): Boolean {
        return parseJsonSubscription(rawBody) != null
    }

    fun parseProxyLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        return when {
            trimmed.startsWith("vless://", ignoreCase = true) -> parseVlessLink(trimmed)
            trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojanLink(trimmed)
            trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocksLink(trimmed)
            trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmessLink(trimmed)
            trimmed.startsWith("socks://", ignoreCase = true) -> parseSocksLink(trimmed)
            else -> error("Unsupported location entry")
        }
    }

    fun parseVlessLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("vless://", ignoreCase = true)) { "Unsupported VLESS entry" }
        val withoutScheme = removeScheme(trimmed, "vless://")
        val (beforeFragment, fragment) = splitOnce(withoutScheme, '#')
        val fragmentDecoded = fragment?.decodeUrlComponent().orEmpty()
        val (beforeQuery, queryRaw) = splitOnce(beforeFragment, '?')
        val query = parseQuery(queryRaw.orEmpty())
        val (userInfo, hostPort) = splitOnce(beforeQuery, '@')
        val resolvedHostPort = hostPort ?: error("Missing VLESS host")
        val (host, port) = parseHostPort(resolvedHostPort)
        return ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            uuid = userInfo.decodeUrlComponent(),
            username = "",
            server = host,
            serverPort = port,
            network = query["type"].orEmpty().ifBlank { "tcp" },
            flow = query["flow"].orEmpty(),
            security = query["security"].orEmpty(),
            sni = query["sni"].orEmpty().ifBlank { host },
            fingerprint = query["fp"].orEmpty().ifBlank { "chrome" },
            publicKey = query["pbk"].orEmpty(),
            shortId = query["sid"].orEmpty(),
            path = query["path"].orEmpty(),
            hostHeader = query["host"].orEmpty(),
            serviceName = query["serviceName"].orEmpty(),
            headerType = query["headerType"].orEmpty().ifBlank { "none" },
            rawLink = trimmed,
        ).also {
            require(it.uuid.isNotBlank()) { "Missing VLESS UUID" }
        }
    }

    fun parseTrojanLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("trojan://", ignoreCase = true)) { "Unsupported Trojan entry" }
        val withoutScheme = removeScheme(trimmed, "trojan://")
        val (beforeFragment, fragment) = splitOnce(withoutScheme, '#')
        val fragmentDecoded = fragment?.decodeUrlComponent().orEmpty()
        val (beforeQuery, queryRaw) = splitOnce(beforeFragment, '?')
        val query = parseQuery(queryRaw.orEmpty())
        val (passwordRaw, hostPort) = splitOnce(beforeQuery, '@')
        val resolvedHostPort = hostPort ?: error("Missing Trojan host")
        val password = passwordRaw.decodeUrlComponent()
        val (host, port) = parseHostPort(resolvedHostPort)
        val security = query["security"].orEmpty().ifBlank { "tls" }
        val path = query["path"].orEmpty()
        val serviceName = query["serviceName"].orEmpty().ifBlank {
            if (query["type"].orEmpty() == "grpc") path else ""
        }
        return ProxyProfile(
            protocol = ProxyProtocol.TROJAN,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            server = host,
            serverPort = port,
            username = "",
            password = password,
            network = query["type"].orEmpty().ifBlank { "tcp" },
            flow = "",
            security = security,
            sni = query["sni"].orEmpty().ifBlank { host },
            fingerprint = query["fp"].orEmpty().ifBlank { "chrome" },
            publicKey = "",
            shortId = "",
            path = if (query["type"].orEmpty() == "grpc") "" else path,
            hostHeader = query["host"].orEmpty(),
            serviceName = serviceName,
            headerType = query["headerType"].orEmpty().ifBlank { "none" },
            rawLink = trimmed,
        ).also {
            require(it.password.isNotBlank()) { "Missing Trojan password" }
        }
    }

    fun parseShadowsocksLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("ss://", ignoreCase = true)) { "Unsupported Shadowsocks entry" }
        val withoutScheme = removeScheme(trimmed, "ss://")
        val (beforeFragment, fragment) = splitOnce(withoutScheme, '#')
        val fragmentDecoded = fragment?.decodeUrlComponent().orEmpty()
        val (beforeQuery, queryRaw) = splitOnce(beforeFragment, '?')
        val query = parseQuery(queryRaw.orEmpty())

        val normalizedEndpoint = if ('@' in beforeQuery) {
            val (authRaw, hostPort) = splitOnce(beforeQuery, '@')
            val resolvedHostPort = hostPort ?: error("Missing Shadowsocks host")
            val decodedAuth = decodeMaybeBase64(authRaw)
            val credentials = if (':' in decodedAuth) decodedAuth else authRaw.decodeUrlComponent()
            "$credentials@$resolvedHostPort"
        } else {
            decodeMaybeBase64(beforeQuery)
        }

        val (userInfo, hostPort) = splitOnce(normalizedEndpoint, '@')
        val resolvedHostPort = hostPort ?: error("Missing Shadowsocks host")
        val (method, passwordRaw) = splitOnce(userInfo, ':')
        val password = passwordRaw?.decodeUrlComponent() ?: error("Missing Shadowsocks password")
        val (host, port) = parseHostPort(resolvedHostPort)
        return ProxyProfile(
            protocol = ProxyProtocol.SHADOWSOCKS,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            server = host,
            serverPort = port,
            username = "",
            password = password,
            method = method.decodeUrlComponent(),
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
            plugin = query["plugin"].orEmpty(),
            rawLink = trimmed,
        )
    }

    fun parseVmessLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("vmess://", ignoreCase = true)) { "Unsupported VMess entry" }
        val payload = removeScheme(trimmed, "vmess://").trim()
        val decoded = decodeMaybeBase64(payload)
        val root = CompactJson.parseToJsonElement(decoded).jsonObject
        val host = root.string("add").trim().ifBlank { error("VMess config is missing host") }
        val network = root.string("net").ifBlank { "tcp" }
        val path = root.string("path")
        return ProxyProfile(
            protocol = ProxyProtocol.VMESS,
            remarks = root.string("ps").ifBlank { host },
            server = host,
            serverPort = root.string("port").toIntOrNull() ?: 443,
            uuid = root.string("id").trim(),
            username = "",
            network = network,
            flow = "",
            security = if (root.string("tls").equals("tls", ignoreCase = true)) "tls" else "",
            sni = root.string("sni"),
            fingerprint = root.string("fp").ifBlank { "chrome" },
            publicKey = "",
            shortId = "",
            path = if (network == "grpc") "" else path,
            hostHeader = root.string("host"),
            serviceName = if (network == "grpc") {
                root.string("serviceName").ifBlank { path }
            } else {
                root.string("serviceName")
            },
            headerType = root.string("type").ifBlank { "none" },
            alterId = root.string("aid").toIntOrNull() ?: 0,
            vmessSecurity = root.string("scy").ifBlank { "auto" },
            rawLink = trimmed,
        ).also {
            require(it.uuid.isNotBlank()) { "Missing VMess UUID" }
        }
    }

    fun parseSocksLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("socks://", ignoreCase = true)) { "Unsupported SOCKS entry" }
        val withoutScheme = removeScheme(trimmed, "socks://")
        val (beforeFragment, fragment) = splitOnce(withoutScheme, '#')
        val fragmentDecoded = fragment?.decodeUrlComponent().orEmpty()
        val (beforeQuery, _) = splitOnce(beforeFragment, '?')
        val (credentialsPart, hostPortCandidate) = splitOnce(beforeQuery, '@')
        val (hostPort, credentials) = if (hostPortCandidate != null) {
            hostPortCandidate to credentialsPart
        } else {
            beforeQuery to null
        }
        val (host, port) = parseHostPort(hostPort)
        val username: String
        val password: String
        if (!credentials.isNullOrBlank()) {
            val (usernameRaw, passwordRaw) = splitOnce(credentials, ':')
            username = usernameRaw.decodeUrlComponent()
            password = passwordRaw?.decodeUrlComponent().orEmpty()
        } else {
            username = ""
            password = ""
        }
        return ProxyProfile(
            protocol = ProxyProtocol.SOCKS,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            server = host,
            serverPort = port,
            uuid = "",
            username = username,
            password = password,
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
            rawLink = trimmed,
        )
    }

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
                kotlinx.serialization.json.JsonObject.serializer(),
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

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        return rawQuery.split("&")
            .mapNotNull { item ->
                if (item.isBlank()) return@mapNotNull null
                val index = item.indexOf('=')
                if (index == -1) {
                    item.decodeUrlComponent() to ""
                } else {
                    item.substring(0, index).decodeUrlComponent() to
                        item.substring(index + 1).decodeUrlComponent()
                }
            }
            .toMap()
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun decodeLooseBase64(data: ByteArray): String {
        val compact = data.decodeToString().replace("\\s+".toRegex(), "")
        return decodeBase64(compact).decodeToString()
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun decodeMaybeBase64(raw: String): String {
        val compact = raw.trim()
        return runCatching { decodeBase64(compact).decodeToString() }
            .getOrElse { compact.decodeUrlComponent() }
    }

    @OptIn(ExperimentalEncodingApi::class)
    private fun decodeBase64(raw: String): ByteArray {
        val normalized = raw.replace("\\s+".toRegex(), "")
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return runCatching {
            Base64.Default.decode(padded)
        }.recoverCatching {
            Base64.UrlSafe.decode(padded)
        }.getOrThrow()
    }

    private fun parseHostPort(hostPort: String): Pair<String, Int> {
        if (hostPort.startsWith("[")) {
            val closingIndex = hostPort.indexOf(']')
            require(closingIndex > 1) { "Invalid IPv6 host" }
            val host = hostPort.substring(1, closingIndex)
            val remainder = hostPort.substring(closingIndex + 1)
            val port = remainder.removePrefix(":").takeIf { it.isNotBlank() }?.toIntOrNull() ?: 443
            return host to port
        }

        val lastColon = hostPort.lastIndexOf(':')
        val colonCount = hostPort.count { it == ':' }
        return if (lastColon > 0 && colonCount == 1) {
            val host = hostPort.substring(0, lastColon)
            val port = hostPort.substring(lastColon + 1).toIntOrNull() ?: 443
            host to port
        } else {
            hostPort to 443
        }
    }

    private fun parseJsonSubscription(rawBody: String): List<ProxyProfile>? {
        val trimmed = rawBody.trim()
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return null
        }
        val root = runCatching { CompactJson.parseToJsonElement(trimmed) }.getOrNull() ?: return null
        val configs = root.subscriptionConfigObjects().takeIf { it.isNotEmpty() } ?: return null
        val profiles = buildList {
            configs.forEachIndexed { index, config ->
                addAll(parseJsonConfigProfiles(config, index))
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

    private fun parseJsonConfigProfiles(
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
                parseJsonOutbound(
                    outbound = outbound,
                    fallbackRemarks = remarks,
                    configIndex = index,
                )
            }.getOrNull()
        }
    }

    private fun parseJsonOutbound(
        outbound: JsonObject,
        fallbackRemarks: String,
        configIndex: Int,
    ): ProxyProfile {
        return when (outbound.string("protocol").lowercase()) {
            "vless" -> parseJsonVnextOutbound(
                protocol = ProxyProtocol.VLESS,
                outbound = outbound,
                fallbackRemarks = fallbackRemarks,
                configIndex = configIndex,
            )
            "vmess" -> parseJsonVnextOutbound(
                protocol = ProxyProtocol.VMESS,
                outbound = outbound,
                fallbackRemarks = fallbackRemarks,
                configIndex = configIndex,
            )
            "trojan" -> parseJsonTrojanOutbound(outbound, fallbackRemarks, configIndex)
            "shadowsocks" -> parseJsonShadowsocksOutbound(outbound, fallbackRemarks, configIndex)
            "socks" -> parseJsonSocksOutbound(outbound, fallbackRemarks, configIndex)
            else -> error("Unsupported JSON outbound protocol")
        }
    }

    private fun parseJsonVnextOutbound(
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
        val security = normalizeJsonSecurity(stream.string("security"))
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
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseJsonTrojanOutbound(
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
        val security = normalizeJsonSecurity(stream.string("security").ifBlank { "tls" })
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
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseJsonShadowsocksOutbound(
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
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseJsonSocksOutbound(
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
        return profile.copy(rawLink = encodeProxyLink(profile))
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

    private fun normalizeJsonSecurity(value: String): String {
        val trimmed = value.trim()
        return if (trimmed.equals("none", ignoreCase = true)) "" else trimmed
    }

    private fun formatHost(host: String): String {
        return if (host.contains(':') && !host.startsWith("[") && !host.endsWith("]")) {
            "[$host]"
        } else {
            host
        }
    }

    private fun looksLikeSupportedLink(value: String): Boolean {
        val normalized = value.trim().lowercase()
        return normalized.startsWith("vless://") ||
            normalized.startsWith("trojan://") ||
            normalized.startsWith("ss://") ||
            normalized.startsWith("vmess://") ||
            normalized.startsWith("socks://")
    }

    private fun removeScheme(value: String, scheme: String): String {
        return value.substring(scheme.length)
    }

    private fun splitOnce(value: String, delimiter: Char): Pair<String, String?> {
        val index = value.indexOf(delimiter)
        return if (index == -1) {
            value to null
        } else {
            value.substring(0, index) to value.substring(index + 1)
        }
    }

    private fun String.decodeUrlComponent(): String {
        if ('%' !in this && '+' !in this) return this
        val output = StringBuilder(length)
        val bytes = mutableListOf<Byte>()

        fun flushBytes() {
            if (bytes.isEmpty()) return
            output.append(bytes.toByteArray().decodeToString())
            bytes.clear()
        }

        var index = 0
        while (index < length) {
            val char = this[index]
            when {
                char == '%' && index + 2 < length -> {
                    val byte = hexByteOrNull(this[index + 1], this[index + 2])
                    if (byte != null) {
                        bytes += byte
                        index += 3
                        continue
                    }
                    flushBytes()
                    output.append(char)
                    index += 1
                }
                char == '+' -> {
                    flushBytes()
                    output.append(' ')
                    index += 1
                }
                else -> {
                    flushBytes()
                    output.append(char)
                    index += 1
                }
            }
        }
        flushBytes()
        return output.toString()
    }

    private fun String.encodeUrlComponent(): String {
        val output = StringBuilder(length)
        encodeToByteArray().forEach { byte ->
            val value = byte.toInt() and 0xFF
            if (isUnreservedUrlByte(value)) {
                output.append(value.toChar())
            } else {
                output.append('%')
                output.append(HEX_DIGITS[value ushr 4])
                output.append(HEX_DIGITS[value and 0x0F])
            }
        }
        return output.toString()
    }

    private fun isUnreservedUrlByte(value: Int): Boolean {
        return value in 'a'.code..'z'.code ||
            value in 'A'.code..'Z'.code ||
            value in '0'.code..'9'.code ||
            value == '-'.code ||
            value == '_'.code ||
            value == '.'.code ||
            value == '~'.code
    }

    private fun hexByteOrNull(first: Char, second: Char): Byte? {
        val high = first.digitToIntOrNull(16) ?: return null
        val low = second.digitToIntOrNull(16) ?: return null
        return ((high shl 4) or low).toByte()
    }

    private fun kotlinx.serialization.json.JsonObject.string(key: String): String {
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

object VlessParser {
    fun parseSubscription(rawBody: String): List<VlessProfile> = ProxyParser.parseSubscription(rawBody)

    fun parseVlessLink(link: String): VlessProfile = ProxyParser.parseVlessLink(link)

    fun encodeVlessLink(profile: VlessProfile): String = ProxyParser.encodeVlessLink(profile)
}

private val HEX_DIGITS = "0123456789ABCDEF"
private val supportedJsonProtocols = setOf("vless", "trojan", "shadowsocks", "vmess", "socks")
