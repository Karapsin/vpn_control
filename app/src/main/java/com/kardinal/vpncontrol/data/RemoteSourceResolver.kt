package com.kardinal.vpncontrol.data

import io.nekohasekai.libbox.Libbox
import android.content.Context
import com.kardinal.vpncontrol.model.VlessProfile
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.URI
import java.util.Base64
import java.util.Locale
import java.util.zip.InflaterInputStream

data class RemoteSourcePreview(
    val kindLabel: String,
    val title: String,
    val detail: String,
    val supported: Boolean,
    val warning: String? = null,
)

data class ResolvedRemoteSource(
    val preview: RemoteSourcePreview,
    val fetchUrl: String? = null,
    val embeddedLocations: List<VlessProfile> = emptyList(),
)

object RemoteSourceResolver {
    private val remoteKeys = listOf(
        "url",
        "remote_url",
        "remoteUrl",
        "subscription_url",
        "subscriptionUrl",
        "profile_url",
        "profileUrl",
    )

    fun preview(raw: String): RemoteSourcePreview? {
        return parse(raw.trim())?.preview
    }

    fun validateProfileSource(raw: String): Result<Unit> = runCatching {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return@runCatching
        when (val source = parse(trimmed)) {
            is UnsupportedRemoteSource -> error(source.errorMessage)
            null -> error("Remote source must be an https:// URL or a supported import link")
            else -> Unit
        }
    }

    suspend fun resolveForFetch(
        context: Context,
        raw: String,
        onStatus: suspend (String) -> Unit = {},
    ): ResolvedRemoteSource {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Remote source is empty" }
        return when (val source = parse(trimmed)) {
            is DirectSubscriptionSource -> ResolvedRemoteSource(
                preview = source.preview,
                fetchUrl = source.url,
            )
            is SingBoxRemoteImportSource -> ResolvedRemoteSource(
                preview = source.preview,
                fetchUrl = source.remoteUrl,
            )
            is VpnImportSource -> {
                when {
                    source.remoteUrl != null -> ResolvedRemoteSource(
                        preview = source.preview,
                        fetchUrl = source.remoteUrl,
                    )
                    source.isGatewayCompatible -> ResolvedRemoteSource(
                        preview = source.preview,
                        embeddedLocations = AmneziaGatewayResolver.resolveLocations(
                            context = context,
                            source = source.toGatewayImport(),
                            onStatus = onStatus,
                        ),
                    )
                    else -> error(source.unsupportedMessage())
                }
            }
            is UnsupportedRemoteSource -> error(source.errorMessage)
            null -> error("Remote source must be an https:// URL or a supported import link")
        }
    }

    fun looksLikeRemoteSourceLink(raw: String): Boolean {
        val trimmed = raw.trim()
        return trimmed.startsWith("http://", ignoreCase = true) ||
            trimmed.startsWith("https://", ignoreCase = true) ||
            trimmed.startsWith("sing-box://import-remote-profile", ignoreCase = true) ||
            trimmed.startsWith("vpn://", ignoreCase = true)
    }

    fun isGatewayBackedVpnImport(raw: String): Boolean {
        return parse(raw.trim()).let { source ->
            source is VpnImportSource && source.isGatewayCompatible && source.remoteUrl == null
        }
    }

    fun redactForDiagnostics(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return "<empty>"
        return when (val source = parse(trimmed)) {
            is DirectSubscriptionSource -> sanitizeUrl(source.url)
            is SingBoxRemoteImportSource -> {
                "sing-box import: name=${source.name} host=${source.host} url=${sanitizeUrl(source.remoteUrl)}"
            }
            is VpnImportSource -> {
                buildString {
                    append("vpn import")
                    source.name.takeIf { it.isNotBlank() }?.let { append(": name=$it") }
                    source.protocol.takeIf { it.isNotBlank() }?.let { append(" protocol=$it") }
                    source.serviceType.takeIf { it.isNotBlank() }?.let { append(" type=$it") }
                    source.remoteUrl?.let { append(" url=${sanitizeUrl(it)}") } ?: append(" gateway=amnezia")
                }
            }
            is UnsupportedRemoteSource -> {
                buildString {
                    append(source.preview.kindLabel)
                    append(": ")
                    append(source.preview.title)
                    source.preview.detail.takeIf { it.isNotBlank() }?.let { append(" ($it)") }
                }
            }
            null -> "<unrecognized remote source>"
        }
    }

    private fun parse(raw: String): ParsedRemoteSource? {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return null
        return when {
            trimmed.startsWith("http://", ignoreCase = true) ||
                trimmed.startsWith("https://", ignoreCase = true) -> {
                val host = trimmed.displayHost()
                DirectSubscriptionSource(
                    url = trimmed,
                    preview = RemoteSourcePreview(
                        kindLabel = "Subscription URL",
                        title = host ?: trimmed,
                        detail = "Direct remote source",
                        supported = true,
                    ),
                )
            }
            trimmed.startsWith("sing-box://import-remote-profile", ignoreCase = true) -> {
                runCatching {
                    val parsed = Libbox.parseRemoteProfileImportLink(trimmed)
                    val name = parsed.name.ifBlank { parsed.host.ifBlank { "Remote profile" } }
                    val remoteUrl = parsed.url
                    val host = parsed.host.ifBlank { remoteUrl.displayHost().orEmpty() }
                    SingBoxRemoteImportSource(
                        name = name,
                        remoteUrl = remoteUrl,
                        host = host,
                        preview = RemoteSourcePreview(
                            kindLabel = "sing-box import link",
                            title = name,
                            detail = if (host.isNotBlank()) {
                                "Fetches remote content from $host"
                            } else {
                                "Fetches remote content from the embedded URL"
                            },
                            supported = true,
                        ),
                    )
                }.getOrElse { error ->
                    UnsupportedRemoteSource(
                        preview = RemoteSourcePreview(
                            kindLabel = "sing-box import link",
                            title = "Unreadable sing-box import link",
                            detail = "The import link could not be parsed",
                            supported = false,
                            warning = "Paste a valid sing-box remote-profile import link or a direct subscription URL.",
                        ),
                        errorMessage = error.message ?: "Unreadable sing-box import link",
                    )
                }
            }
            trimmed.startsWith("vpn://", ignoreCase = true) -> parseVpnImport(trimmed)
            else -> null
        }
    }

    private fun parseVpnImport(raw: String): ParsedRemoteSource {
        return runCatching {
            val payload = decodeVpnPayload(raw)
            val apiConfig = payload.optJSONObject("api_config")
            val name = payload.optString("name")
                .ifBlank { payload.optString("description") }
                .ifBlank { apiConfig?.optString("service_type").orEmpty() }
                .ifBlank { "VPN import" }
            val protocol = apiConfig?.optString("service_protocol").orEmpty()
            val serviceType = apiConfig?.optString("service_type").orEmpty()
            val country = apiConfig?.optString("user_country_code").orEmpty()
            val remoteUrl = extractRemoteUrl(payload)
            val authData = payload.optJSONObject("auth_data")
            val detail = listOf(protocol, serviceType, country.uppercase(Locale.ROOT))
                .filter { it.isNotBlank() }
                .joinToString(" • ")
                .ifBlank { "Provider import" }
            val gatewayCompatible = authData != null && serviceType.isNotBlank()

            if (remoteUrl != null) {
                val host = remoteUrl.displayHost().orEmpty()
                VpnImportSource(
                    name = name,
                    protocol = protocol,
                    serviceType = serviceType,
                    userCountryCode = country,
                    authData = authData,
                    remoteUrl = remoteUrl,
                    isGatewayCompatible = gatewayCompatible,
                    preview = RemoteSourcePreview(
                        kindLabel = "VPN import link",
                        title = name,
                        detail = if (host.isNotBlank()) {
                            "$detail • fetches remote content from $host"
                        } else {
                            detail
                        },
                        supported = true,
                    ),
                )
            } else if (gatewayCompatible) {
                VpnImportSource(
                    name = name,
                    protocol = protocol,
                    serviceType = serviceType,
                    userCountryCode = country,
                    authData = authData,
                    remoteUrl = null,
                    isGatewayCompatible = true,
                    preview = RemoteSourcePreview(
                        kindLabel = "VPN import link",
                        title = name,
                        detail = "$detail • resolves locations through Amnezia Gateway",
                        supported = true,
                        warning = "The app will fetch available VLESS locations from this provider import.",
                    ),
                )
            } else {
                UnsupportedRemoteSource(
                    preview = RemoteSourcePreview(
                        kindLabel = "VPN import link",
                        title = name,
                        detail = detail,
                        supported = false,
                        warning = "This import contains provider credentials or another unsupported format, not a VLESS location list.",
                    ),
                    errorMessage = buildString {
                        append("This vpn:// import link is not supported here")
                        if (protocol.isNotBlank() || serviceType.isNotBlank()) {
                            append(": ")
                            append(listOf(protocol, serviceType).filter { it.isNotBlank() }.joinToString(" / "))
                        }
                        append(". Use a normal subscription URL instead.")
                    },
                )
            }
        }.getOrElse {
            UnsupportedRemoteSource(
                preview = RemoteSourcePreview(
                    kindLabel = "VPN import link",
                    title = "Unreadable VPN import link",
                    detail = "The import payload could not be decoded",
                    supported = false,
                    warning = "Use a normal subscription URL or another supported import link.",
                ),
                errorMessage = "Unreadable vpn:// import link",
            )
        }
    }

    private fun decodeVpnPayload(raw: String): JSONObject {
        val encoded = raw.removePrefix("vpn://").trim()
        require(encoded.isNotBlank()) { "vpn:// import link is empty" }
        val payload = Base64.getUrlDecoder().decode(encoded.padBase64())
        val decodedText = sequenceOf(
            payload.copyOfRange(4.coerceAtMost(payload.size), payload.size),
            payload,
        ).mapNotNull { candidate ->
            runCatching {
                InflaterInputStream(ByteArrayInputStream(candidate)).bufferedReader().use { it.readText() }
            }.getOrNull()
        }.firstOrNull()
        require(!decodedText.isNullOrBlank()) { "Could not inflate vpn:// payload" }
        return JSONObject(decodedText)
    }

    private fun extractRemoteUrl(root: JSONObject): String? {
        remoteKeys.forEach { key ->
            root.optString(key).trim().takeIf { it.startsWithHttpScheme() }?.let { return it }
        }
        val nestedCandidates = listOfNotNull(
            root.optJSONObject("api_config"),
            root.optJSONObject("config"),
            root.optJSONObject("profile"),
        )
        nestedCandidates.forEach { nested ->
            remoteKeys.forEach { key ->
                nested.optString(key).trim().takeIf { it.startsWithHttpScheme() }?.let { return it }
            }
        }
        return null
    }

    private fun sanitizeUrl(raw: String): String {
        return runCatching {
            val uri = URI(raw)
            val host = uri.host ?: return@runCatching raw
            buildString {
                append(uri.scheme ?: "https")
                append("://")
                append(host)
                if (uri.port != -1) {
                    append(':')
                    append(uri.port)
                }
                uri.path?.takeIf { it.isNotBlank() }?.let { append(it) }
                if (!uri.query.isNullOrBlank()) {
                    append("?<redacted>")
                }
                if (!uri.fragment.isNullOrBlank()) {
                    append("#<redacted>")
                }
            }
        }.getOrDefault(raw)
    }

    private fun String.displayHost(): String? {
        return runCatching { URI(this).host }
            .getOrNull()
            ?.removePrefix("www.")
            ?.takeIf { it.isNotBlank() }
    }

    private fun String.startsWithHttpScheme(): Boolean {
        return startsWith("http://", ignoreCase = true) || startsWith("https://", ignoreCase = true)
    }

    private fun String.padBase64(): String {
        val padding = (4 - length % 4) % 4
        return this + "=".repeat(padding)
    }

    private sealed interface ParsedRemoteSource {
        val preview: RemoteSourcePreview
    }

    private data class DirectSubscriptionSource(
        val url: String,
        override val preview: RemoteSourcePreview,
    ) : ParsedRemoteSource

    private data class SingBoxRemoteImportSource(
        val name: String,
        val remoteUrl: String,
        val host: String,
        override val preview: RemoteSourcePreview,
    ) : ParsedRemoteSource

    private data class VpnImportSource(
        val name: String,
        val protocol: String,
        val serviceType: String,
        val userCountryCode: String,
        val authData: JSONObject?,
        val remoteUrl: String?,
        val isGatewayCompatible: Boolean,
        override val preview: RemoteSourcePreview,
    ) : ParsedRemoteSource {
        fun toGatewayImport(): AmneziaGatewayImport {
            return AmneziaGatewayImport(
                name = name,
                serviceType = serviceType,
                userCountryCode = userCountryCode,
                authData = authData ?: error("Amnezia gateway auth data is missing"),
            )
        }

        fun unsupportedMessage(): String {
            return buildString {
                append("This vpn:// import link is not supported here")
                if (protocol.isNotBlank() || serviceType.isNotBlank()) {
                    append(": ")
                    append(listOf(protocol, serviceType).filter { it.isNotBlank() }.joinToString(" / "))
                }
                append(". Use a normal subscription URL instead.")
            }
        }
    }

    private data class UnsupportedRemoteSource(
        override val preview: RemoteSourcePreview,
        val errorMessage: String,
    ) : ParsedRemoteSource
}
