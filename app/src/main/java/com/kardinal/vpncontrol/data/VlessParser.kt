package com.kardinal.vpncontrol.data

import android.util.Base64
import com.kardinal.vpncontrol.model.VlessProfile
import java.net.URLEncoder
import java.net.URLDecoder

object VlessParser {
    fun parseSubscription(rawBody: String): List<VlessProfile> {
        val directLines = rawBody.lines().map { it.trim() }.filter { it.isNotBlank() }
        val lines = if (directLines.any { it.startsWith("vless://") }) {
            directLines
        } else {
            decodeLooseBase64(rawBody.toByteArray())
                .lines()
                .map { it.trim() }
                .filter { it.isNotBlank() }
        }

        val profiles = lines.filter { it.startsWith("vless://") }.map(::parseVlessLink)
        require(profiles.isNotEmpty()) { "Subscription format is not recognized as a VLESS link list" }
        return profiles
    }

    fun parseVlessLink(link: String): VlessProfile {
        val trimmed = link.trim()
        require(trimmed.startsWith("vless://")) { "Unsupported subscription entry" }
        val withoutScheme = trimmed.removePrefix("vless://")
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
        val hostPort = authPair.second ?: error("Missing user info")
        val hostPair = splitOnce(hostPort, ':')
        val host = hostPair.first
        val portStr = hostPair.second
        val port = portStr?.toIntOrNull() ?: 443
        return VlessProfile(
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
        )
    }

    fun encodeVlessLink(profile: VlessProfile): String {
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
            append(profile.server)
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
        val padding = (4 - compact.length % 4) % 4
        val normalized = compact + "=".repeat(padding)
        return String(Base64.decode(normalized, Base64.DEFAULT), Charsets.UTF_8)
    }

    private fun String.decodeUrlComponent(): String = URLDecoder.decode(this, Charsets.UTF_8.name())
    private fun String.encodeUrlComponent(): String = URLEncoder.encode(this, Charsets.UTF_8.name())

    private fun splitOnce(value: String, delimiter: Char): Pair<String, String?> {
        val index = value.indexOf(delimiter)
        return if (index == -1) value to null else value.substring(0, index) to value.substring(index + 1)
    }
}
