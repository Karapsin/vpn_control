package com.kardinal.vpncontrol.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object DiagnosticsSanitizer {
    private val proxyLinkRegex = Regex("""(?i)\b(vless|trojan|ss|vmess|socks)://[^\s"'<>]+""")
    private val httpUrlRegex = Regex("""(?i)\bhttps?://[^\s"'<>]+""")
    private val tlsUrlRegex = Regex("""(?i)\btls://[^\s"'<>]+""")
    private val uuidRegex = Regex(
        """(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b""",
    )
    private val publicIpv4Regex = Regex("""\b(?:\d{1,3}\.){3}\d{1,3}\b""")
    private val homePathRegex = Regex("""/home/[^/\s]+""")
    private val userFieldRegex = Regex("""(?i)\buser:\s*[^,\s]+""")
    private val sensitiveKeyValueRegex = Regex(
        """(?i)\b(uuid|password|public_key|short_id|raw_link|source_url|server|server_name|sni|pbk|sid)=([^\s|,]+)""",
    )

    fun redactText(raw: String): String {
        if (raw.isBlank()) return raw
        return raw
            .replace(proxyLinkRegex) { match ->
                "<${match.groupValues[1].lowercase()}-link-redacted>"
            }
            .replace(httpUrlRegex) { match ->
                redactHttpUrl(match.value)
            }
            .replace(tlsUrlRegex, "tls://<redacted>")
            .replace(uuidRegex, "<uuid-redacted>")
            .replace(publicIpv4Regex) { match ->
                if (isPrivateIpv4(match.value)) match.value else "<ip-redacted>"
            }
            .replace(homePathRegex, "/home/<user>")
            .replace(userFieldRegex, "user: <user>")
            .replace(sensitiveKeyValueRegex) { match ->
                "${match.groupValues[1]}=<redacted>"
            }
    }

    fun summarizeStoredLocation(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return "profile_present=false"
        return runCatching {
            val profile = LocationConfigs.decodeStoredLocation(trimmed)
            listOf(
                "profile_present=true",
                "protocol=${profile.protocol.name.lowercase()}",
                "remarks=${redactText(profile.remarks)}",
                "server_present=${profile.server.isNotBlank()}",
                "server_port=${profile.serverPort}",
                "raw_link_present=${profile.rawLink.isNotBlank()}",
                "custom_config_present=${profile.customConfigJson.isNotBlank()}",
            ).joinToString(separator = "\n")
        }.getOrElse { error ->
            listOf(
                "profile_present=true",
                "parse_error=${error.message ?: error::class.simpleName.orEmpty()}",
            ).joinToString(separator = "\n")
        }
    }

    fun summarizeStoredLocations(rawLocations: List<String>, sampleLimit: Int = 12): String {
        if (rawLocations.isEmpty()) return "count=0"
        val summaries = rawLocations.map { raw ->
            runCatching { LocationConfigs.decodeStoredLocation(raw) }
        }
        val validProfiles = summaries.mapNotNull { it.getOrNull() }
        val protocolCounts = validProfiles
            .groupingBy { it.protocol.name.lowercase() }
            .eachCount()
            .toSortedMap()
            .entries
            .joinToString(",") { "${it.key}:${it.value}" }
            .ifBlank { "<none>" }
        val sampleNames = validProfiles
            .take(sampleLimit)
            .joinToString(",") { redactText(it.remarks) }
            .ifBlank { "<none>" }
        return listOf(
            "count=${rawLocations.size}",
            "valid_count=${validProfiles.size}",
            "invalid_count=${summaries.count { it.isFailure }}",
            "protocols=$protocolCounts",
            "sample_names=$sampleNames",
        ).joinToString(separator = "\n")
    }

    fun summarizeSingBoxConfig(raw: String?): String {
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isBlank()) return "config_present=false"
        return runCatching {
            val root = CompactJson.parseToJsonElement(trimmed).jsonObject
            val inbounds = root.arrayOrEmpty("inbounds")
            val outbounds = root.arrayOrEmpty("outbounds")
            val proxy = outbounds
                .mapNotNull { it as? JsonObject }
                .firstOrNull { it.string("tag") == "proxy" }
            val routeRules = root["route"]
                ?.jsonObject
                ?.arrayOrEmpty("rules")
                .orEmpty()
            val dnsServers = root["dns"]
                ?.jsonObject
                ?.arrayOrEmpty("servers")
                .orEmpty()
            val dnsServerTypes = dnsServers
                .mapNotNull { (it as? JsonObject)?.string("type")?.takeIf(String::isNotBlank) }
                .joinToString(",")
                .ifBlank { "<none>" }
            val detouredDnsServers = dnsServers.count {
                (it as? JsonObject)?.string("detour")?.isNotBlank() == true
            }
            val inboundTypes = inbounds
                .mapNotNull { (it as? JsonObject)?.string("type")?.takeIf(String::isNotBlank) }
                .joinToString(",")
                .ifBlank { "<none>" }
            listOf(
                "config_present=true",
                "inbound_types=$inboundTypes",
                "proxy_outbound_type=${proxy?.string("type") ?: "<none>"}",
                "proxy_server_present=${proxy?.string("server")?.isNotBlank() == true}",
                "proxy_server_port=${proxy?.int("server_port") ?: 0}",
                "outbound_count=${outbounds.size}",
                "route_rules_count=${routeRules.size}",
                "dns_servers_count=${dnsServers.size}",
                "dns_server_types=$dnsServerTypes",
                "dns_detoured_servers_count=$detouredDnsServers",
            ).joinToString(separator = "\n")
        }.getOrElse { error ->
            listOf(
                "config_present=true",
                "parse_error=${error.message ?: error::class.simpleName.orEmpty()}",
            ).joinToString(separator = "\n")
        }
    }

    private fun redactHttpUrl(raw: String): String {
        val schemeEnd = raw.indexOf("://")
        if (schemeEnd < 0) return "<url-redacted>"
        val scheme = raw.substring(0, schemeEnd).lowercase()
        val rest = raw.substring(schemeEnd + 3)
        val host = rest.substringBefore('/').substringBefore('?').substringBefore('#')
        return if (host.isBlank()) {
            "$scheme://<redacted>"
        } else {
            "$scheme://$host/<redacted>"
        }
    }

    private fun isPrivateIpv4(raw: String): Boolean {
        val parts = raw.split('.').mapNotNull { it.toIntOrNull() }
        if (parts.size != 4 || parts.any { it !in 0..255 }) return false
        val first = parts[0]
        val second = parts[1]
        return first == 10 ||
            first == 127 ||
            first == 0 ||
            first == 169 && second == 254 ||
            first == 172 && second in 16..31 ||
            first == 192 && second == 168
    }

    private fun JsonObject.string(key: String): String =
        this[key]?.jsonPrimitive?.contentOrNull.orEmpty()

    private fun JsonObject.int(key: String): Int? =
        this[key]?.jsonPrimitive?.intOrNull

    private fun JsonObject.arrayOrEmpty(key: String): JsonArray =
        this[key]?.jsonArray ?: JsonArray(emptyList())
}
