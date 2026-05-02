package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol

internal object ProxyParserEngine {
    fun parseSubscription(rawBody: String): List<ProxyProfile> {
        JsonSubscriptionParser.parse(rawBody)?.let { return it }

        val directLines = rawBody.lines().map { it.trim() }.filter { it.isNotBlank() }
        if (directLines.any(ProxyLinkParser::looksLikeSupportedLink)) {
            return ProxyLinkParser.parseProxyLinkLines(directLines)
        }

        parseClashSubscription(rawBody)?.let { return it }

        val decoded = decodeLooseBase64(rawBody.encodeToByteArray())
        JsonSubscriptionParser.parse(decoded)?.let { return it }
        parseClashSubscription(decoded)?.let { return it }

        val decodedLines = decoded.lines().map { it.trim() }.filter { it.isNotBlank() }
        if (decodedLines.any(ProxyLinkParser::looksLikeSupportedLink)) {
            return ProxyLinkParser.parseProxyLinkLines(decodedLines)
        }

        error("Subscription format is not recognized as a supported proxy link list")
    }

    internal fun supportsJsonSubscription(rawBody: String): Boolean {
        return JsonSubscriptionParser.parse(rawBody) != null
    }

    fun parseProxyLink(link: String): ProxyProfile =
        ProxyLinkParser.parseProxyLink(link)

    fun parseVlessLink(link: String): ProxyProfile =
        ProxyLinkParser.parseVlessLink(link)

    fun parseTrojanLink(link: String): ProxyProfile =
        ProxyLinkParser.parseTrojanLink(link)

    fun parseShadowsocksLink(link: String): ProxyProfile =
        ProxyLinkParser.parseShadowsocksLink(link)

    fun parseVmessLink(link: String): ProxyProfile =
        ProxyLinkParser.parseVmessLink(link)

    fun parseSocksLink(link: String): ProxyProfile =
        ProxyLinkParser.parseSocksLink(link)

    fun encodeProxyLink(profile: ProxyProfile): String =
        ProxyLinkEncoder.encodeProxyLink(profile)

    fun encodeVlessLink(profile: ProxyProfile): String =
        ProxyLinkEncoder.encodeVlessLink(profile)

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

}
