package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.ProxyProfile
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

data class LocationsExportDocument(
    val fileName: String,
    val content: String,
)

object LocationConfigs {
    private const val FORMAT_TYPE = "vpn_control_locations"
    private const val FORMAT_VERSION = 1
    private const val CUSTOM_CONFIG_TYPE = "custom"
    private const val CUSTOM_CONFIG_FALLBACK_SERVER = "custom-config"

    fun parseLocationInput(raw: String): ProxyProfile {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Location config is empty" }
        require(!isUnsupportedVpnImport(trimmed)) {
            "vpn:// imports are not supported. Use a normal subscription URL or add locations manually."
        }
        require(!looksLikeRemoteSourceLink(trimmed)) {
            "This is a remote source link. Add it in Profile Source on the Profile tab."
        }
        return if (looksLikeProxyLink(trimmed)) {
            ProxyParser.parseProxyLink(trimmed)
        } else {
            parseProfileJson(CompactJson.parseToJsonElement(trimmed).jsonObject)
        }
    }

    fun decodeStoredLocation(raw: String): ProxyProfile {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Stored location is empty" }
        return if (trimmed.startsWith("{")) {
            parseProfileJson(CompactJson.parseToJsonElement(trimmed).jsonObject)
        } else {
            ProxyParser.parseProxyLink(trimmed)
        }
    }

    fun normalizeStoredReference(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return ""
        return runCatching { encodeStoredLocation(parseLocationInput(trimmed)) }
            .getOrDefault(trimmed)
    }

    fun selectedStoredReference(selectedProfileJson: String, selectedProfileRawLink: String): String {
        return selectedProfileJson.ifBlank {
            selectedProfileRawLink
                .takeIf { it.isNotBlank() }
                ?.let(::normalizeStoredReference)
                .orEmpty()
        }
    }

    fun encodeStoredLocation(profile: ProxyProfile): String =
        CompactJson.encodeToString(JsonObject.serializer(), profileToJson(profile))

    fun prettyStoredLocation(raw: String): String {
        val profile = decodeStoredLocation(raw)
        return if (profile.protocol == ProxyProtocol.CUSTOM && profile.customConfigJson.isNotBlank()) {
            prettyJsonOrRaw(profile.customConfigJson)
        } else {
            PrettyJson.encodeToString(JsonObject.serializer(), profileToJson(profile))
        }
    }

    fun export(storedLocations: List<String>): LocationsExportDocument {
        val timestamp = Clock.System.now().toString()
        val payload = buildJsonArray {
            storedLocations.forEach { raw ->
                add(profileToJson(decodeStoredLocation(raw)))
            }
        }
        val content = PrettyJson.encodeToString(
            JsonObject.serializer(),
            buildJsonObject {
                put("type", JsonPrimitive(FORMAT_TYPE))
                put("version", JsonPrimitive(FORMAT_VERSION))
                put("exported_at", JsonPrimitive(timestamp))
                put("locations", payload)
            },
        )
        return LocationsExportDocument(
            fileName = "vpn-control-locations-${timestamp.replace(':', '-')}.json",
            content = content,
        )
    }

    fun import(raw: String): List<String> {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Locations import is empty" }
        val root = CompactJson.parseToJsonElement(trimmed)
        val objects = when (root) {
            is JsonArray -> readArray(root)
            is JsonObject -> when {
                "locations" in root -> readArray(root.requiredArray("locations"))
                looksLikeProfile(root) -> listOf(root)
                else -> error("Locations JSON format is not recognized")
            }
            else -> error("Locations import must be JSON")
        }
        return objects.map { encodeStoredLocation(parseProfileJson(it)) }
    }

    private fun readArray(array: JsonArray): List<JsonObject> {
        return buildList {
            array.forEachIndexed { index, item ->
                when (item) {
                    is JsonObject -> add(item)
                    is JsonPrimitive -> {
                        require(item.isString) { "Unsupported location entry at index ${index + 1}" }
                        add(profileToJson(ProxyParser.parseProxyLink(item.content)))
                    }
                    else -> error("Unsupported location entry at index ${index + 1}")
                }
            }
        }
    }

    private fun looksLikeProfile(root: JsonObject): Boolean {
        return "server" in root ||
            "uuid" in root ||
            "password" in root ||
            "method" in root ||
            "custom_config_json" in root ||
            "customConfigJson" in root ||
            "outbounds" in root ||
            "inbounds" in root ||
            "raw_link" in root ||
            "rawLink" in root
    }

    private fun parseProfileJson(root: JsonObject): ProxyProfile {
        if (looksLikeCustomConfig(root)) {
            val embedded = root.string("custom_config_json")
                .ifBlank { root.string("customConfigJson") }
                .trim()
            val customConfigJson = embedded.ifBlank {
                PrettyJson.encodeToString(JsonObject.serializer(), root)
            }
            return ProxyProfile(
                protocol = ProxyProtocol.CUSTOM,
                remarks = root.string("remarks")
                    .ifBlank { root.string("name") }
                    .ifBlank { "Custom Config" },
                uuid = "",
                server = root.string("server").ifBlank { CUSTOM_CONFIG_FALLBACK_SERVER },
                serverPort = root.int("server_port", root.int("serverPort", 0)),
                password = "",
                method = "",
                network = "custom",
                flow = "",
                security = "",
                sni = root.string("sni").ifBlank { CUSTOM_CONFIG_FALLBACK_SERVER },
                fingerprint = "chrome",
                publicKey = "",
                shortId = "",
                path = "",
                hostHeader = "",
                serviceName = "",
                headerType = "none",
                alterId = 0,
                vmessSecurity = "auto",
                plugin = "",
                pluginOptions = "",
                rawLink = root.string("raw_link").ifBlank { root.string("rawLink") },
                customConfigJson = customConfigJson,
            )
        }

        val rawLink = root.string("raw_link").ifBlank { root.string("rawLink") }
        if (rawLink.isNotBlank() && "server" !in root && "uuid" !in root && "password" !in root) {
            return ProxyParser.parseProxyLink(rawLink)
        }

        val protocol = parseProtocol(root.string("protocol").ifBlank { root.string("type") })
        val server = root.string("server").trim()
        require(server.isNotBlank()) { "Location JSON is missing server" }
        val uuid = root.string("uuid").trim()
        val username = root.string("username").trim()
        val password = root.string("password").trim()
        val method = root.string("method").trim()

        when (protocol) {
            ProxyProtocol.VLESS, ProxyProtocol.VMESS -> require(uuid.isNotBlank()) {
                "Location JSON is missing uuid"
            }
            ProxyProtocol.TROJAN -> require(password.isNotBlank()) {
                "Location JSON is missing password"
            }
            ProxyProtocol.SHADOWSOCKS -> {
                require(method.isNotBlank()) { "Location JSON is missing method" }
                require(password.isNotBlank()) { "Location JSON is missing password" }
            }
            ProxyProtocol.SOCKS -> Unit
            ProxyProtocol.CUSTOM -> error("Custom configs must use custom JSON format")
        }

        return ProxyProfile(
            protocol = protocol,
            remarks = root.string("remarks")
                .ifBlank { root.string("name") }
                .ifBlank { server },
            uuid = uuid,
            username = username,
            server = server,
            serverPort = root.int("server_port", root.int("serverPort", 443)),
            password = password,
            method = method,
            network = root.string("network").ifBlank { root.string("transport") }.ifBlank { "tcp" },
            flow = root.string("flow"),
            security = root.string("security"),
            sni = root.string("sni").ifBlank { server },
            fingerprint = root.string("fingerprint")
                .ifBlank { root.string("fp") }
                .ifBlank { "chrome" },
            publicKey = root.string("public_key").ifBlank { root.string("publicKey") },
            shortId = root.string("short_id").ifBlank { root.string("shortId") },
            path = root.string("path"),
            hostHeader = root.string("host_header").ifBlank { root.string("hostHeader") },
            serviceName = root.string("service_name").ifBlank { root.string("serviceName") },
            headerType = root.string("header_type")
                .ifBlank { root.string("headerType") }
                .ifBlank { "none" },
            alterId = root.int("alter_id", root.int("alterId", 0)),
            vmessSecurity = root.string("vmess_security")
                .ifBlank { root.string("vmessSecurity") }
                .ifBlank { "auto" },
            plugin = root.string("plugin"),
            pluginOptions = root.string("plugin_options").ifBlank { root.string("pluginOptions") },
            rawLink = rawLink,
        )
    }

    private fun profileToJson(profile: ProxyProfile): JsonObject {
        if (profile.protocol == ProxyProtocol.CUSTOM) {
            return buildJsonObject {
                put("type", JsonPrimitive(CUSTOM_CONFIG_TYPE))
                put("protocol", JsonPrimitive(CUSTOM_CONFIG_TYPE))
                put("remarks", JsonPrimitive(profile.remarks))
                put("server", JsonPrimitive(profile.server))
                put("server_port", JsonPrimitive(profile.serverPort))
                put("raw_link", JsonPrimitive(profile.rawLink))
                put("custom_config_json", JsonPrimitive(profile.customConfigJson))
            }
        }
        return buildJsonObject {
            put("type", JsonPrimitive(profile.protocol.name.lowercase()))
            put("protocol", JsonPrimitive(profile.protocol.name.lowercase()))
            put("remarks", JsonPrimitive(profile.remarks))
            put("uuid", JsonPrimitive(profile.uuid))
            put("username", JsonPrimitive(profile.username))
            put("server", JsonPrimitive(profile.server))
            put("server_port", JsonPrimitive(profile.serverPort))
            put("password", JsonPrimitive(profile.password))
            put("method", JsonPrimitive(profile.method))
            put("network", JsonPrimitive(profile.network))
            put("flow", JsonPrimitive(profile.flow))
            put("security", JsonPrimitive(profile.security))
            put("sni", JsonPrimitive(profile.sni))
            put("fingerprint", JsonPrimitive(profile.fingerprint))
            put("public_key", JsonPrimitive(profile.publicKey))
            put("short_id", JsonPrimitive(profile.shortId))
            put("path", JsonPrimitive(profile.path))
            put("host_header", JsonPrimitive(profile.hostHeader))
            put("service_name", JsonPrimitive(profile.serviceName))
            put("header_type", JsonPrimitive(profile.headerType))
            put("alter_id", JsonPrimitive(profile.alterId))
            put("vmess_security", JsonPrimitive(profile.vmessSecurity))
            put("plugin", JsonPrimitive(profile.plugin))
            put("plugin_options", JsonPrimitive(profile.pluginOptions))
            put("raw_link", JsonPrimitive(profile.rawLink))
        }
    }

    private fun parseProtocol(raw: String): ProxyProtocol {
        return when (raw.trim().lowercase()) {
            "", "vless" -> ProxyProtocol.VLESS
            "trojan" -> ProxyProtocol.TROJAN
            "shadowsocks", "ss" -> ProxyProtocol.SHADOWSOCKS
            "vmess" -> ProxyProtocol.VMESS
            "socks", "socks5" -> ProxyProtocol.SOCKS
            "custom", "custom_config" -> ProxyProtocol.CUSTOM
            else -> error("Unsupported location protocol: $raw")
        }
    }

    private fun looksLikeCustomConfig(root: JsonObject): Boolean {
        val protocol = root.string("protocol").ifBlank { root.string("type") }.trim().lowercase()
        return protocol == CUSTOM_CONFIG_TYPE ||
            protocol == "custom_config" ||
            "custom_config_json" in root ||
            "customConfigJson" in root ||
            (("outbounds" in root || "inbounds" in root) &&
                "server" !in root &&
                "uuid" !in root &&
                "password" !in root &&
                "method" !in root)
    }

    private fun prettyJsonOrRaw(raw: String): String {
        val trimmed = raw.trim()
        return runCatching {
            when {
                trimmed.startsWith("{") || trimmed.startsWith("[") ->
                    PrettyJson.encodeToString(
                        JsonElement.serializer(),
                        CompactJson.parseToJsonElement(trimmed),
                    )
                else -> trimmed
            }
        }.getOrDefault(trimmed)
    }

    private fun JsonObject.requiredArray(key: String): JsonArray {
        return this[key]?.jsonArray ?: error("Locations JSON format is not recognized")
    }

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
    }

    private fun JsonObject.int(key: String, default: Int): Int {
        val value = this[key]?.jsonPrimitive ?: return default
        return value.intOrNull() ?: default
    }

    private fun JsonPrimitive.intOrNull(): Int? {
        return contentOrNull?.toIntOrNull()
    }
}
