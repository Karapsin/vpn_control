package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
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

internal object ProxyParserEngine {
    fun parseSubscription(rawBody: String): List<ProxyProfile> {
        parseJsonSubscription(rawBody)?.let { return it }

        val directLines = rawBody.lines().map { it.trim() }.filter { it.isNotBlank() }
        if (directLines.any(::looksLikeSupportedLink)) {
            return parseProxyLinkLines(directLines)
        }

        parseClashSubscription(rawBody)?.let { return it }

        val decoded = decodeLooseBase64(rawBody.encodeToByteArray())
        parseJsonSubscription(decoded)?.let { return it }
        parseClashSubscription(decoded)?.let { return it }

        val decodedLines = decoded.lines().map { it.trim() }.filter { it.isNotBlank() }
        if (decodedLines.any(::looksLikeSupportedLink)) {
            return parseProxyLinkLines(decodedLines)
        }

        error("Subscription format is not recognized as a supported proxy link list")
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

    private fun parseProxyLinkLines(lines: List<String>): List<ProxyProfile> {
        val profiles = lines.mapNotNull { line ->
            runCatching { parseProxyLink(line) }.getOrNull()
        }
        require(profiles.isNotEmpty()) {
            "Subscription format is not recognized as a supported proxy link list"
        }
        return profiles
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

    private fun parseClashSubscription(rawBody: String): List<ProxyProfile>? {
        if (!looksLikeClashSubscription(rawBody)) {
            return null
        }
        val entries = parseClashProxyEntries(rawBody)
        if (entries.isEmpty()) {
            return null
        }
        val profiles = entries.mapNotNull { entry ->
            runCatching { parseClashProxy(entry) }.getOrNull()
        }.distinctBy { it.rawLink }
        return profiles.takeIf { it.isNotEmpty() }
    }

    private fun looksLikeClashSubscription(rawBody: String): Boolean {
        return rawBody.lineSequence().any { line ->
            val trimmed = stripYamlComment(line).trim()
            trimmed == "proxies:" || trimmed.startsWith("proxies: ")
        }
    }

    private fun parseClashProxyEntries(rawBody: String): List<Map<String, String>> {
        val entries = mutableListOf<Map<String, String>>()
        var inProxies = false
        var proxiesIndent = -1
        var current: MutableMap<String, String>? = null
        val prefixStack = mutableListOf<Pair<Int, String>>()

        fun finishCurrent() {
            current?.takeIf { it.isNotEmpty() }?.let { entries += it.toMap() }
            current = null
            prefixStack.clear()
        }

        rawBody.lines().forEach { rawLine ->
            val withoutComment = stripYamlComment(rawLine).trimEnd()
            if (withoutComment.isBlank()) {
                return@forEach
            }
            val indent = withoutComment.leadingSpaceCount()
            val trimmed = withoutComment.trim()

            if (!inProxies) {
                if (trimmed == "proxies:" || trimmed.startsWith("proxies: ")) {
                    inProxies = true
                    proxiesIndent = indent
                    val inlineValue = trimmed.removePrefix("proxies:").trim()
                    if (inlineValue.startsWith("[") && inlineValue.endsWith("]")) {
                        parseInlineYamlList(inlineValue).forEach { item ->
                            parseInlineYamlMap(item).takeIf { it.isNotEmpty() }?.let { entries += it }
                        }
                    }
                }
                return@forEach
            }

            if (indent <= proxiesIndent && !trimmed.startsWith("- ")) {
                finishCurrent()
                return entries
            }

            if (trimmed.startsWith("- ")) {
                finishCurrent()
                current = mutableMapOf()
                val item = trimmed.removePrefix("- ").trim()
                when {
                    item.startsWith("{") -> current?.putAll(parseInlineYamlMap(item))
                    item.isNotBlank() -> parseYamlKeyValue(item)?.let { (key, value) ->
                        current?.put(normalizeYamlKey(key), normalizeYamlScalar(value))
                    }
                }
                return@forEach
            }

            val target = current ?: return@forEach
            val (keyRaw, valueRaw) = parseYamlKeyValue(trimmed) ?: return@forEach
            while (prefixStack.isNotEmpty() && prefixStack.last().first >= indent) {
                prefixStack.removeAt(prefixStack.lastIndex)
            }
            val key = normalizeYamlKey(keyRaw)
            val parent = prefixStack.lastOrNull()?.second
            val fullKey = if (parent.isNullOrBlank()) key else "$parent.$key"
            if (valueRaw.isBlank()) {
                prefixStack += indent to fullKey
            } else {
                val normalizedValue = normalizeYamlScalar(valueRaw)
                if (normalizedValue.startsWith("{") && normalizedValue.endsWith("}")) {
                    target.putAll(parseInlineYamlMap(normalizedValue, fullKey))
                } else {
                    target[fullKey] = normalizedValue
                }
            }
        }

        finishCurrent()
        return entries
    }

    private fun parseClashProxy(entry: Map<String, String>): ProxyProfile {
        return when (entry.clashString("type").lowercase()) {
            "vless" -> parseClashVless(entry)
            "vmess" -> parseClashVmess(entry)
            "trojan" -> parseClashTrojan(entry)
            "ss", "shadowsocks" -> parseClashShadowsocks(entry)
            "socks", "socks5" -> parseClashSocks(entry)
            else -> error("Unsupported Clash proxy protocol")
        }
    }

    private fun parseClashVless(entry: Map<String, String>): ProxyProfile {
        val host = entry.clashString("server").ifBlank { error("Missing VLESS host") }
        val network = normalizeClashNetwork(entry.clashString("network", "net").ifBlank { "tcp" })
        val security = when {
            entry.clashString("security").equals("reality", ignoreCase = true) -> "reality"
            entry.clashString("reality-opts.public-key", "reality-opts.short-id").isNotBlank() -> "reality"
            entry.clashBoolean("tls") -> "tls"
            else -> ""
        }
        val profile = ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = entry.clashString("name").ifBlank { host },
            server = host,
            serverPort = entry.clashInt("port") ?: 443,
            uuid = entry.clashString("uuid").trim(),
            username = "",
            password = "",
            method = "",
            network = network,
            flow = entry.clashString("flow"),
            security = security,
            sni = if (security.isBlank()) "" else entry.clashString("servername", "sni").ifBlank { host },
            fingerprint = entry.clashString("client-fingerprint", "fingerprint").ifBlank { "chrome" },
            publicKey = entry.clashString("reality-opts.public-key", "reality-opts.publickey"),
            shortId = entry.clashString("reality-opts.short-id", "reality-opts.shortid"),
            path = clashTransportPath(entry, network),
            hostHeader = entry.clashString("ws-opts.headers.host", "ws-opts.host", "host"),
            serviceName = clashGrpcServiceName(entry),
            headerType = "none",
            rawLink = "",
        )
        require(profile.uuid.isNotBlank()) { "Missing VLESS UUID" }
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseClashVmess(entry: Map<String, String>): ProxyProfile {
        val host = entry.clashString("server").ifBlank { error("Missing VMess host") }
        val network = normalizeClashNetwork(entry.clashString("network", "net").ifBlank { "tcp" })
        val security = if (entry.clashBoolean("tls")) "tls" else ""
        val profile = ProxyProfile(
            protocol = ProxyProtocol.VMESS,
            remarks = entry.clashString("name").ifBlank { host },
            server = host,
            serverPort = entry.clashInt("port") ?: 443,
            uuid = entry.clashString("uuid").trim(),
            username = "",
            password = "",
            method = "",
            network = network,
            flow = "",
            security = security,
            sni = if (security.isBlank()) "" else entry.clashString("servername", "sni").ifBlank { host },
            fingerprint = entry.clashString("client-fingerprint", "fingerprint").ifBlank { "chrome" },
            publicKey = "",
            shortId = "",
            path = clashTransportPath(entry, network),
            hostHeader = entry.clashString("ws-opts.headers.host", "ws-opts.host", "host"),
            serviceName = clashGrpcServiceName(entry),
            headerType = "none",
            alterId = entry.clashInt("alterid", "alter-id") ?: 0,
            vmessSecurity = entry.clashString("cipher", "security").ifBlank { "auto" },
            rawLink = "",
        )
        require(profile.uuid.isNotBlank()) { "Missing VMess UUID" }
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseClashTrojan(entry: Map<String, String>): ProxyProfile {
        val host = entry.clashString("server").ifBlank { error("Missing Trojan host") }
        val network = normalizeClashNetwork(entry.clashString("network", "net").ifBlank { "tcp" })
        val security = if (entry.clashBoolean("tls", default = true)) "tls" else ""
        val profile = ProxyProfile(
            protocol = ProxyProtocol.TROJAN,
            remarks = entry.clashString("name").ifBlank { host },
            server = host,
            serverPort = entry.clashInt("port") ?: 443,
            username = "",
            password = entry.clashString("password"),
            method = "",
            network = network,
            flow = "",
            security = security,
            sni = if (security.isBlank()) "" else entry.clashString("servername", "sni").ifBlank { host },
            fingerprint = entry.clashString("client-fingerprint", "fingerprint").ifBlank { "chrome" },
            publicKey = "",
            shortId = "",
            path = clashTransportPath(entry, network),
            hostHeader = entry.clashString("ws-opts.headers.host", "ws-opts.host", "host"),
            serviceName = clashGrpcServiceName(entry),
            headerType = "none",
            rawLink = "",
        )
        require(profile.password.isNotBlank()) { "Missing Trojan password" }
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseClashShadowsocks(entry: Map<String, String>): ProxyProfile {
        val host = entry.clashString("server").ifBlank { error("Missing Shadowsocks host") }
        val profile = ProxyProfile(
            protocol = ProxyProtocol.SHADOWSOCKS,
            remarks = entry.clashString("name").ifBlank { host },
            server = host,
            serverPort = entry.clashInt("port") ?: 8388,
            username = "",
            password = entry.clashString("password"),
            method = entry.clashString("cipher", "method"),
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
            plugin = entry.clashString("plugin"),
            rawLink = "",
        )
        require(profile.password.isNotBlank()) { "Missing Shadowsocks password" }
        require(profile.method.isNotBlank()) { "Missing Shadowsocks method" }
        return profile.copy(rawLink = encodeProxyLink(profile))
    }

    private fun parseClashSocks(entry: Map<String, String>): ProxyProfile {
        val host = entry.clashString("server").ifBlank { error("Missing SOCKS host") }
        val profile = ProxyProfile(
            protocol = ProxyProtocol.SOCKS,
            remarks = entry.clashString("name").ifBlank { host },
            server = host,
            serverPort = entry.clashInt("port") ?: 1080,
            uuid = "",
            username = entry.clashString("username", "user"),
            password = entry.clashString("password", "pass"),
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

    private fun clashTransportPath(entry: Map<String, String>, network: String): String {
        return when (network) {
            "ws" -> entry.clashString("ws-opts.path", "path")
            "grpc" -> ""
            else -> entry.clashString("h2-opts.path", "http-opts.path")
        }
    }

    private fun clashGrpcServiceName(entry: Map<String, String>): String {
        return entry.clashString("grpc-opts.grpc-service-name", "grpc-opts.grpcservicename", "serviceName")
    }

    private fun normalizeClashNetwork(value: String): String {
        return when (value.trim().lowercase()) {
            "", "tcp" -> "tcp"
            "websocket" -> "ws"
            "h2", "http" -> "http"
            else -> value.trim().lowercase()
        }
    }

    private fun Map<String, String>.clashString(vararg keys: String): String {
        keys.forEach { key ->
            val value = this[normalizeYamlKey(key)]?.trim().orEmpty()
            if (value.isNotBlank()) return value
        }
        return ""
    }

    private fun Map<String, String>.clashInt(vararg keys: String): Int? {
        return clashString(*keys).toIntOrNull()
    }

    private fun Map<String, String>.clashBoolean(key: String, default: Boolean = false): Boolean {
        val raw = this[normalizeYamlKey(key)]?.trim()?.lowercase() ?: return default
        return when (raw) {
            "true", "yes", "on", "1" -> true
            "false", "no", "off", "0" -> false
            else -> default
        }
    }

    private fun parseInlineYamlList(raw: String): List<String> {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) {
            return emptyList()
        }
        return splitYamlTopLevel(trimmed.substring(1, trimmed.length - 1), ',')
            .map(String::trim)
            .filter(String::isNotBlank)
    }

    private fun parseInlineYamlMap(raw: String, prefix: String = ""): Map<String, String> {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
            return emptyMap()
        }
        val body = trimmed.substring(1, trimmed.length - 1)
        val output = mutableMapOf<String, String>()
        splitYamlTopLevel(body, ',').forEach { item ->
            val (keyRaw, valueRaw) = splitYamlTopLevelOnce(item, ':') ?: return@forEach
            val key = normalizeYamlKey(keyRaw)
            val fullKey = listOf(prefix, key).filter(String::isNotBlank).joinToString(".")
            val value = normalizeYamlScalar(valueRaw)
            if (value.startsWith("{") && value.endsWith("}")) {
                output += parseInlineYamlMap(value, fullKey)
            } else {
                output[fullKey] = value
            }
        }
        return output
    }

    private fun parseYamlKeyValue(raw: String): Pair<String, String>? {
        return splitYamlTopLevelOnce(raw, ':')?.let { (key, value) ->
            key.trim().takeIf { it.isNotBlank() }?.let { it to value.trim() }
        }
    }

    private fun splitYamlTopLevelOnce(raw: String, delimiter: Char): Pair<String, String>? {
        var quote: Char? = null
        var braceDepth = 0
        var bracketDepth = 0
        raw.forEachIndexed { index, char ->
            when {
                quote != null -> {
                    if (char == quote && raw.getOrNull(index - 1) != '\\') quote = null
                }
                char == '"' || char == '\'' -> quote = char
                char == '{' -> braceDepth += 1
                char == '}' && braceDepth > 0 -> braceDepth -= 1
                char == '[' -> bracketDepth += 1
                char == ']' && bracketDepth > 0 -> bracketDepth -= 1
                char == delimiter && braceDepth == 0 && bracketDepth == 0 ->
                    return raw.substring(0, index) to raw.substring(index + 1)
            }
        }
        return null
    }

    private fun splitYamlTopLevel(raw: String, delimiter: Char): List<String> {
        val output = mutableListOf<String>()
        var quote: Char? = null
        var braceDepth = 0
        var bracketDepth = 0
        var start = 0
        raw.forEachIndexed { index, char ->
            when {
                quote != null -> {
                    if (char == quote && raw.getOrNull(index - 1) != '\\') quote = null
                }
                char == '"' || char == '\'' -> quote = char
                char == '{' -> braceDepth += 1
                char == '}' && braceDepth > 0 -> braceDepth -= 1
                char == '[' -> bracketDepth += 1
                char == ']' && bracketDepth > 0 -> bracketDepth -= 1
                char == delimiter && braceDepth == 0 && bracketDepth == 0 -> {
                    output += raw.substring(start, index)
                    start = index + 1
                }
            }
        }
        output += raw.substring(start)
        return output
    }

    private fun stripYamlComment(raw: String): String {
        var quote: Char? = null
        raw.forEachIndexed { index, char ->
            when {
                quote != null -> {
                    if (char == quote && raw.getOrNull(index - 1) != '\\') quote = null
                }
                char == '"' || char == '\'' -> quote = char
                char == '#' && (index == 0 || raw[index - 1].isWhitespace()) -> return raw.substring(0, index)
            }
        }
        return raw
    }

    private fun normalizeYamlKey(raw: String): String {
        return normalizeYamlScalar(raw).lowercase()
    }

    private fun normalizeYamlScalar(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.equals("null", ignoreCase = true) || trimmed == "~") {
            return ""
        }
        if (trimmed.length >= 2) {
            val first = trimmed.first()
            val last = trimmed.last()
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                val inner = trimmed.substring(1, trimmed.length - 1)
                return if (first == '"') {
                    inner.replace("\\\"", "\"").replace("\\\\", "\\")
                } else {
                    inner.replace("''", "'")
                }
            }
        }
        return trimmed
    }

    private fun String.leadingSpaceCount(): Int {
        return takeWhile { it == ' ' }.length
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

private val HEX_DIGITS = "0123456789ABCDEF"
private val supportedJsonProtocols = setOf("vless", "trojan", "shadowsocks", "vmess", "socks")
