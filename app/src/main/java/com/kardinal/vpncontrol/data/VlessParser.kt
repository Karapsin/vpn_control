package com.kardinal.vpncontrol.data

import android.util.Base64
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.VlessProfile
import org.json.JSONObject
import java.net.URLEncoder
import java.net.URLDecoder
import java.util.Locale

object ProxyParser {
    fun parseSubscription(rawBody: String): List<ProxyProfile> {
        val directLines = rawBody.lines().map { it.trim() }.filter { it.isNotBlank() }
        val lines = if (directLines.any(::looksLikeSupportedLink)) {
            directLines
        } else {
            decodeLooseBase64(rawBody.toByteArray())
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

    fun parseProxyLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        return when {
            trimmed.startsWith("vless://", ignoreCase = true) -> parseVlessLink(trimmed)
            trimmed.startsWith("trojan://", ignoreCase = true) -> parseTrojanLink(trimmed)
            trimmed.startsWith("ss://", ignoreCase = true) -> parseShadowsocksLink(trimmed)
            trimmed.startsWith("vmess://", ignoreCase = true) -> parseVmessLink(trimmed)
            else -> error("Unsupported location entry")
        }
    }

    fun parseVlessLink(link: String): ProxyProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("vless://", ignoreCase = true)) { "Unsupported VLESS entry" }
        val withoutScheme = removeScheme(trimmed, "vless://")
        val fragmentPair = splitOnce(withoutScheme, '#')
        val beforeFragment = fragmentPair.first
        val fragment = fragmentPair.second
        val fragmentDecoded = fragment?.decodeUrlComponent().orEmpty()
        val queryPair = splitOnce(beforeFragment, '?')
        val beforeQuery = queryPair.first
        val queryRaw = queryPair.second
        val query = parseQuery(queryRaw.orEmpty())
        val authPair = splitOnce(beforeQuery, '@')
        val userInfo = authPair.first
        val hostPort = authPair.second ?: error("Missing VLESS host")
        val (host, port) = parseHostPort(hostPort)
        return ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            uuid = userInfo.decodeUrlComponent(),
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
        val fragmentPair = splitOnce(withoutScheme, '#')
        val beforeFragment = fragmentPair.first
        val fragmentDecoded = fragmentPair.second?.decodeUrlComponent().orEmpty()
        val queryPair = splitOnce(beforeFragment, '?')
        val beforeQuery = queryPair.first
        val query = parseQuery(queryPair.second.orEmpty())
        val authPair = splitOnce(beforeQuery, '@')
        val password = authPair.first.decodeUrlComponent()
        val hostPort = authPair.second ?: error("Missing Trojan host")
        val (host, port) = parseHostPort(hostPort)
        val security = query["security"].orEmpty().ifBlank {
            if (query["sni"].orEmpty().isNotBlank()) "tls" else ""
        }
        val path = query["path"].orEmpty()
        val serviceName = query["serviceName"].orEmpty().ifBlank {
            if (query["type"].orEmpty() == "grpc") path else ""
        }
        return ProxyProfile(
            protocol = ProxyProtocol.TROJAN,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            server = host,
            serverPort = port,
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
        val fragmentPair = splitOnce(withoutScheme, '#')
        val beforeFragment = fragmentPair.first
        val fragmentDecoded = fragmentPair.second?.decodeUrlComponent().orEmpty()
        val queryPair = splitOnce(beforeFragment, '?')
        val beforeQuery = queryPair.first
        val query = parseQuery(queryPair.second.orEmpty())

        val normalizedEndpoint = if ('@' in beforeQuery) {
            val authPair = splitOnce(beforeQuery, '@')
            val decodedAuth = decodeMaybeBase64(authPair.first)
            val credentials = if (':' in decodedAuth) decodedAuth else authPair.first.decodeUrlComponent()
            "$credentials@${authPair.second ?: error("Missing Shadowsocks host")}"
        } else {
            decodeMaybeBase64(beforeQuery)
        }

        val authPair = splitOnce(normalizedEndpoint, '@')
        val userInfo = authPair.first
        val hostPort = authPair.second ?: error("Missing Shadowsocks host")
        val credentialPair = splitOnce(userInfo, ':')
        val method = credentialPair.first.decodeUrlComponent()
        val password = credentialPair.second?.decodeUrlComponent() ?: error("Missing Shadowsocks password")
        val (host, port) = parseHostPort(hostPort)
        return ProxyProfile(
            protocol = ProxyProtocol.SHADOWSOCKS,
            remarks = if (fragmentDecoded.isNotBlank()) fragmentDecoded else host,
            server = host,
            serverPort = port,
            password = password,
            method = method,
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
        val root = JSONObject(decoded)
        val host = root.optString("add").trim().ifBlank { error("VMess config is missing host") }
        val network = root.optString("net").ifBlank { "tcp" }
        val path = root.optString("path")
        return ProxyProfile(
            protocol = ProxyProtocol.VMESS,
            remarks = root.optString("ps").ifBlank { host },
            server = host,
            serverPort = root.optString("port").toIntOrNull() ?: 443,
            uuid = root.optString("id").trim(),
            network = network,
            flow = "",
            security = if (root.optString("tls").equals("tls", ignoreCase = true)) "tls" else "",
            sni = root.optString("sni").ifBlank { host },
            fingerprint = root.optString("fp").ifBlank { "chrome" },
            publicKey = "",
            shortId = "",
            path = if (network == "grpc") "" else path,
            hostHeader = root.optString("host"),
            serviceName = if (network == "grpc") {
                root.optString("serviceName").ifBlank { path }
            } else {
                root.optString("serviceName")
            },
            headerType = root.optString("type").ifBlank { "none" },
            alterId = root.optString("aid").toIntOrNull() ?: 0,
            vmessSecurity = root.optString("scy").ifBlank { "auto" },
            rawLink = trimmed,
        ).also {
            require(it.uuid.isNotBlank()) { "Missing VMess UUID" }
        }
    }

    fun encodeProxyLink(profile: ProxyProfile): String {
        return when (profile.protocol) {
            ProxyProtocol.VLESS -> encodeVlessLink(profile)
            ProxyProtocol.TROJAN -> encodeTrojanLink(profile)
            ProxyProtocol.SHADOWSOCKS -> encodeShadowsocksLink(profile)
            ProxyProtocol.VMESS -> encodeVmessLink(profile)
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

    private fun encodeShadowsocksLink(profile: ProxyProfile): String {
        val userInfo = "${profile.method}:${profile.password}"
        val encodedUserInfo = Base64.encodeToString(
            userInfo.toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP or Base64.URL_SAFE,
        ).trimEnd('=')
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

    private fun encodeVmessLink(profile: ProxyProfile): String {
        val payload = JSONObject()
            .put("v", "2")
            .put("ps", profile.remarks)
            .put("add", profile.server)
            .put("port", profile.serverPort.toString())
            .put("id", profile.uuid)
            .put("aid", profile.alterId.toString())
            .put("scy", profile.vmessSecurity.ifBlank { "auto" })
            .put("net", profile.network.ifBlank { "tcp" })
            .put("type", profile.headerType.ifBlank { "none" })
            .put("host", profile.hostHeader)
            .put("path", if (profile.network == "grpc") profile.serviceName else profile.path)
            .put("tls", if (profile.security.isNotBlank()) "tls" else "")
            .put("sni", profile.sni)
            .put("fp", profile.fingerprint)
        val encoded = Base64.encodeToString(
            payload.toString().toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP or Base64.URL_SAFE,
        ).trimEnd('=')
        return "vmess://$encoded"
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        return rawQuery.split("&")
            .mapNotNull { item ->
                if (item.isBlank()) return@mapNotNull null
                val idx = item.indexOf('=')
                if (idx == -1) {
                    item.decodeUrlComponent() to ""
                } else {
                    item.substring(0, idx).decodeUrlComponent() to item.substring(idx + 1).decodeUrlComponent()
                }
            }
            .toMap()
    }

    private fun decodeLooseBase64(data: ByteArray): String {
        val compact = data.toString(Charsets.UTF_8).replace("\\s+".toRegex(), "")
        return String(decodeBase64(compact), Charsets.UTF_8)
    }

    private fun decodeMaybeBase64(raw: String): String {
        val compact = raw.trim()
        return runCatching { String(decodeBase64(compact), Charsets.UTF_8) }
            .getOrElse { compact.decodeUrlComponent() }
    }

    private fun decodeBase64(raw: String): ByteArray {
        val normalized = raw.replace("\\s+".toRegex(), "")
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        return runCatching {
            Base64.decode(padded, Base64.DEFAULT)
        }.recoverCatching {
            Base64.decode(padded, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
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

    private fun formatHost(host: String): String {
        return if (host.contains(':') && !host.startsWith("[") && !host.endsWith("]")) {
            "[$host]"
        } else {
            host
        }
    }

    private fun looksLikeSupportedLink(value: String): Boolean {
        val normalized = value.trim().lowercase(Locale.ROOT)
        return normalized.startsWith("vless://") ||
            normalized.startsWith("trojan://") ||
            normalized.startsWith("ss://") ||
            normalized.startsWith("vmess://")
    }

    private fun removeScheme(value: String, scheme: String): String {
        return value.substring(scheme.length)
    }

    private fun String.decodeUrlComponent(): String = URLDecoder.decode(this, Charsets.UTF_8.name())
    private fun String.encodeUrlComponent(): String = URLEncoder.encode(this, Charsets.UTF_8.name())

    private fun splitOnce(value: String, delimiter: Char): Pair<String, String?> {
        val index = value.indexOf(delimiter)
        return if (index == -1) value to null else value.substring(0, index) to value.substring(index + 1)
    }
}

object VlessParser {
    fun parseSubscription(rawBody: String): List<VlessProfile> = ProxyParser.parseSubscription(rawBody)

    fun parseVlessLink(link: String): VlessProfile = ProxyParser.parseVlessLink(link)

    fun encodeVlessLink(profile: VlessProfile): String = ProxyParser.encodeVlessLink(profile)
}
