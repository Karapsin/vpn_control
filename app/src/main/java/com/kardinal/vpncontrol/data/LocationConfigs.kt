package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.VlessProfile
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

    fun parseLocationInput(raw: String): VlessProfile {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Location config is empty" }
        require(!RemoteSourceResolver.isUnsupportedVpnImport(trimmed)) {
            "vpn:// imports are not supported. Use a normal subscription URL or add VLESS locations manually."
        }
        require(!RemoteSourceResolver.looksLikeRemoteSourceLink(trimmed)) {
            "This is a remote source link. Add it in Profile Source on the Profile tab."
        }
        return if (trimmed.startsWith("vless://")) {
            VlessParser.parseVlessLink(trimmed)
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
            VlessParser.parseVlessLink(trimmed)
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

    fun prettyStoredLocation(raw: String): String = profileToJson(decodeStoredLocation(raw)).toString(2)

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
                    is String -> add(profileToJson(VlessParser.parseVlessLink(item)))
                    else -> error("Unsupported location entry at index ${index + 1}")
                }
            }
        }
    }

    private fun looksLikeProfile(root: JSONObject): Boolean {
        return root.has("server") || root.has("uuid") || root.has("raw_link") || root.has("rawLink")
    }

    private fun parseProfileJson(root: JSONObject): VlessProfile {
        val rawLink = root.optString("raw_link").ifBlank { root.optString("rawLink") }
        if (rawLink.isNotBlank() && !root.has("server") && !root.has("uuid")) {
            return VlessParser.parseVlessLink(rawLink)
        }

        val server = root.optString("server").trim()
        val uuid = root.optString("uuid").trim()
        require(server.isNotBlank()) { "Location JSON is missing server" }
        require(uuid.isNotBlank()) { "Location JSON is missing uuid" }

        return VlessProfile(
            remarks = root.optString("remarks")
                .ifBlank { root.optString("name") }
                .ifBlank { server },
            uuid = uuid,
            server = server,
            serverPort = root.optInt("server_port", root.optInt("serverPort", 443)),
            network = root.optString("network").ifBlank { root.optString("type") }.ifBlank { "tcp" },
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
            rawLink = rawLink,
        )
    }

    private fun profileToJson(profile: VlessProfile): JSONObject {
        return JSONObject()
            .put("type", "vless")
            .put("remarks", profile.remarks)
            .put("uuid", profile.uuid)
            .put("server", profile.server)
            .put("server_port", profile.serverPort)
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
            .put("raw_link", profile.rawLink)
    }
}
