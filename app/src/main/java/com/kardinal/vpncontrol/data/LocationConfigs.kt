package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.VlessProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

data class LocationsExportDocument(
    val fileName: String,
    val content: String,
)

object LocationConfigs {
    private const val FORMAT_TYPE = "vpn_control_locations"
    private const val FORMAT_VERSION = 1
    private const val CUSTOM_CONFIG_TYPE = "custom"
    private const val CUSTOM_CONFIG_FALLBACK_SERVER = "custom-config"

    fun parseLocationInput(raw: String): VlessProfile {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Location config is empty" }
        require(!RemoteSourceResolver.isUnsupportedVpnImport(trimmed)) {
            "vpn:// imports are not supported. Use a normal subscription URL or add locations manually."
        }
        require(!RemoteSourceResolver.looksLikeRemoteSourceLink(trimmed)) {
            "This is a remote source link. Add it in Profile Source on the Profile tab."
        }
        return if (looksLikeProxyLink(trimmed)) {
            ProxyParser.parseProxyLink(trimmed)
        } else {
            parseProfileJson(JSONObject(trimmed))
        }
    }

    fun decodeStoredLocation(raw: String): VlessProfile {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Stored location is empty" }
        return if (trimmed.startsWith("{")) {
            parseProfileJson(JSONObject(trimmed))
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

    fun encodeStoredLocation(profile: VlessProfile): String = profileToJson(profile).toString()

    fun prettyStoredLocation(raw: String): String {
        val profile = decodeStoredLocation(raw)
        return if (profile.protocol == ProxyProtocol.CUSTOM && profile.customConfigJson.isNotBlank()) {
            prettyJsonOrRaw(profile.customConfigJson)
        } else {
            profileToJson(profile).toString(2)
        }
    }

    fun export(storedLocations: List<String>): LocationsExportDocument {
        val payload = JSONArray().apply {
            storedLocations.forEach { raw ->
                put(profileToJson(decodeStoredLocation(raw)))
            }
        }
        val timestamp = Instant.now().toString()
        val content = JSONObject()
            .put("type", FORMAT_TYPE)
            .put("version", FORMAT_VERSION)
            .put("exported_at", timestamp)
            .put("locations", payload)
            .toString(2)
        return LocationsExportDocument(
            fileName = "vpn-control-locations-${timestamp.replace(':', '-')}.json",
            content = content,
        )
    }

    fun import(raw: String): List<String> {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Locations import is empty" }
        val objects = when {
            trimmed.startsWith("[") -> readArray(JSONArray(trimmed))
            trimmed.startsWith("{") -> {
                val root = JSONObject(trimmed)
                when {
                    root.has("locations") -> readArray(root.getJSONArray("locations"))
                    looksLikeProfile(root) -> listOf(root)
                    else -> error("Locations JSON format is not recognized")
                }
            }
            else -> error("Locations import must be JSON")
        }
        return objects.map { encodeStoredLocation(parseProfileJson(it)) }
    }

    private fun readArray(array: JSONArray): List<JSONObject> {
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.opt(index)
                when (item) {
                    is JSONObject -> add(item)
                    is String -> add(profileToJson(ProxyParser.parseProxyLink(item)))
                    else -> error("Unsupported location entry at index ${index + 1}")
                }
            }
        }
    }

    private fun looksLikeProfile(root: JSONObject): Boolean {
        return root.has("server") ||
            root.has("uuid") ||
            root.has("password") ||
            root.has("method") ||
            root.has("custom_config_json") ||
            root.has("customConfigJson") ||
            root.has("outbounds") ||
            root.has("inbounds") ||
            root.has("raw_link") ||
            root.has("rawLink")
    }

    private fun parseProfileJson(root: JSONObject): VlessProfile {
        if (looksLikeCustomConfig(root)) {
            val embedded = root.optString("custom_config_json")
                .ifBlank { root.optString("customConfigJson") }
                .trim()
            val customConfigJson = embedded.ifBlank { root.toString(2) }
            return VlessProfile(
                protocol = ProxyProtocol.CUSTOM,
                remarks = root.optString("remarks")
                    .ifBlank { root.optString("name") }
                    .ifBlank { "Custom Config" },
                uuid = "",
                server = root.optString("server").ifBlank { CUSTOM_CONFIG_FALLBACK_SERVER },
                serverPort = root.optInt("server_port", root.optInt("serverPort", 0)),
                password = "",
                method = "",
                network = "custom",
                flow = "",
                security = "",
                sni = root.optString("sni").ifBlank { CUSTOM_CONFIG_FALLBACK_SERVER },
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
                rawLink = root.optString("raw_link").ifBlank { root.optString("rawLink") },
                customConfigJson = customConfigJson,
            )
        }

        val rawLink = root.optString("raw_link").ifBlank { root.optString("rawLink") }
        if (rawLink.isNotBlank() && !root.has("server") && !root.has("uuid") && !root.has("password")) {
            return ProxyParser.parseProxyLink(rawLink)
        }

        val protocol = parseProtocol(
            root.optString("protocol").ifBlank { root.optString("type") },
        )
        val server = root.optString("server").trim()
        require(server.isNotBlank()) { "Location JSON is missing server" }
        val uuid = root.optString("uuid").trim()
        val username = root.optString("username").trim()
        val password = root.optString("password").trim()
        val method = root.optString("method").trim()

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

        return VlessProfile(
            protocol = protocol,
            remarks = root.optString("remarks")
                .ifBlank { root.optString("name") }
                .ifBlank { server },
            uuid = uuid,
            username = username,
            server = server,
            serverPort = root.optInt("server_port", root.optInt("serverPort", 443)),
            password = password,
            method = method,
            network = root.optString("network").ifBlank { root.optString("transport") }.ifBlank { "tcp" },
            flow = root.optString("flow"),
            security = root.optString("security"),
            sni = root.optString("sni").ifBlank { server },
            fingerprint = root.optString("fingerprint")
                .ifBlank { root.optString("fp") }
                .ifBlank { "chrome" },
            publicKey = root.optString("public_key").ifBlank { root.optString("publicKey") },
            shortId = root.optString("short_id").ifBlank { root.optString("shortId") },
            path = root.optString("path"),
            hostHeader = root.optString("host_header").ifBlank { root.optString("hostHeader") },
            serviceName = root.optString("service_name").ifBlank { root.optString("serviceName") },
            headerType = root.optString("header_type").ifBlank { root.optString("headerType") }.ifBlank { "none" },
            alterId = root.optInt("alter_id", root.optInt("alterId", 0)),
            vmessSecurity = root.optString("vmess_security")
                .ifBlank { root.optString("vmessSecurity") }
                .ifBlank { "auto" },
            plugin = root.optString("plugin"),
            pluginOptions = root.optString("plugin_options").ifBlank { root.optString("pluginOptions") },
            rawLink = rawLink,
        )
    }

    private fun profileToJson(profile: VlessProfile): JSONObject {
        if (profile.protocol == ProxyProtocol.CUSTOM) {
            return JSONObject()
                .put("type", CUSTOM_CONFIG_TYPE)
                .put("protocol", CUSTOM_CONFIG_TYPE)
                .put("remarks", profile.remarks)
                .put("server", profile.server)
                .put("server_port", profile.serverPort)
                .put("raw_link", profile.rawLink)
                .put("custom_config_json", profile.customConfigJson)
        }
        return JSONObject()
            .put("type", profile.protocol.name.lowercase())
            .put("protocol", profile.protocol.name.lowercase())
            .put("remarks", profile.remarks)
            .put("uuid", profile.uuid)
            .put("username", profile.username)
            .put("server", profile.server)
            .put("server_port", profile.serverPort)
            .put("password", profile.password)
            .put("method", profile.method)
            .put("network", profile.network)
            .put("flow", profile.flow)
            .put("security", profile.security)
            .put("sni", profile.sni)
            .put("fingerprint", profile.fingerprint)
            .put("public_key", profile.publicKey)
            .put("short_id", profile.shortId)
            .put("path", profile.path)
            .put("host_header", profile.hostHeader)
            .put("service_name", profile.serviceName)
            .put("header_type", profile.headerType)
            .put("alter_id", profile.alterId)
            .put("vmess_security", profile.vmessSecurity)
            .put("plugin", profile.plugin)
            .put("plugin_options", profile.pluginOptions)
            .put("raw_link", profile.rawLink)
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

    private fun looksLikeProxyLink(raw: String): Boolean {
        val normalized = raw.lowercase()
        return normalized.startsWith("vless://") ||
            normalized.startsWith("trojan://") ||
            normalized.startsWith("ss://") ||
            normalized.startsWith("vmess://") ||
            normalized.startsWith("socks://")
    }

    private fun looksLikeCustomConfig(root: JSONObject): Boolean {
        val protocol = root.optString("protocol").ifBlank { root.optString("type") }.trim().lowercase()
        return protocol == CUSTOM_CONFIG_TYPE ||
            protocol == "custom_config" ||
            root.has("custom_config_json") ||
            root.has("customConfigJson") ||
            ((root.has("outbounds") || root.has("inbounds")) &&
                !root.has("server") &&
                !root.has("uuid") &&
                !root.has("password") &&
                !root.has("method"))
    }

    private fun prettyJsonOrRaw(raw: String): String {
        val trimmed = raw.trim()
        return runCatching {
            when {
                trimmed.startsWith("{") -> JSONObject(trimmed).toString(2)
                trimmed.startsWith("[") -> JSONArray(trimmed).toString(2)
                else -> trimmed
            }
        }.getOrDefault(trimmed)
    }
}
