package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal object ProxyLinkParser {
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

    fun parseProxyLinkLines(lines: List<String>): List<ProxyProfile> {
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

    fun looksLikeSupportedLink(value: String): Boolean {
        val normalized = value.trim().lowercase()
        return normalized.startsWith("vless://") ||
            normalized.startsWith("trojan://") ||
            normalized.startsWith("ss://") ||
            normalized.startsWith("vmess://") ||
            normalized.startsWith("socks://")
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

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
    }
}
