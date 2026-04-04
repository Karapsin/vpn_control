package com.kardinal.vpncontrol.data

import io.nekohasekai.libbox.Libbox
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
)

object RemoteSourceResolver {
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

    fun resolveForFetch(raw: String): ResolvedRemoteSource {
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

    fun isUnsupportedVpnImport(raw: String): Boolean {
        return raw.trim().startsWith("vpn://", ignoreCase = true)
    }

    fun redactForDiagnostics(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return "<empty>"
        return when (val source = parse(trimmed)) {
            is DirectSubscriptionSource -> sanitizeUrl(source.url)
            is SingBoxRemoteImportSource -> {
                "sing-box import: name=${source.name} host=${source.host} url=${sanitizeUrl(source.remoteUrl)}"
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
            trimmed.startsWith("http://", ignoreCase = true) -> {
                UnsupportedRemoteSource(
                    preview = RemoteSourcePreview(
                        kindLabel = "Subscription URL",
                        title = trimmed.displayHost() ?: trimmed,
                        detail = "Insecure HTTP subscriptions are not supported",
                        supported = false,
                        warning = "Use an https:// subscription URL.",
                    ),
                    errorMessage = "HTTP subscription URLs are not supported. Use https:// instead.",
                )
            }
            trimmed.startsWith("https://", ignoreCase = true) -> {
                val host = trimmed.displayHost()
                if (host.isNullOrBlank()) {
                    UnsupportedRemoteSource(
                        preview = RemoteSourcePreview(
                            kindLabel = "Subscription URL",
                            title = "Unreadable subscription URL",
                            detail = "The URL must include a valid HTTPS host",
                            supported = false,
                            warning = "Paste a valid https:// subscription URL.",
                        ),
                        errorMessage = "Remote source must be a valid https:// URL with a host.",
                    )
                } else {
                    DirectSubscriptionSource(
                        url = trimmed,
                        preview = RemoteSourcePreview(
                            kindLabel = "Subscription URL",
                            title = host,
                            detail = "Direct remote source",
                            supported = true,
                        ),
                    )
                }
            }
            trimmed.startsWith("sing-box://import-remote-profile", ignoreCase = true) -> {
                runCatching {
                    val parsed = Libbox.parseRemoteProfileImportLink(trimmed)
                    val name = parsed.name.ifBlank { parsed.host.ifBlank { "Remote profile" } }
                    val remoteUrl = parsed.url
                    val host = parsed.host.ifBlank { remoteUrl.displayHost().orEmpty() }
                    if (!remoteUrl.startsWith("https://", ignoreCase = true) || host.isBlank()) {
                        UnsupportedRemoteSource(
                            preview = RemoteSourcePreview(
                                kindLabel = "sing-box import link",
                                title = name,
                                detail = "Only valid HTTPS remote URLs are supported",
                                supported = false,
                                warning = "Use a sing-box import link that resolves to a valid https:// URL.",
                            ),
                            errorMessage = "This sing-box import resolves to an invalid or non-HTTPS URL. Use a valid https:// URL instead.",
                        )
                    } else {
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
                    }
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
            val detail = listOf(protocol, serviceType, country.uppercase(Locale.ROOT))
                .filter { it.isNotBlank() }
                .joinToString(" • ")
                .ifBlank { "Unsupported provider import" }

            UnsupportedRemoteSource(
                preview = RemoteSourcePreview(
                    kindLabel = "VPN import link",
                    title = name,
                    detail = detail,
                    supported = false,
                    warning = "Amnezia and other vpn:// imports are not supported. Use a normal subscription URL or add VLESS locations manually.",
                ),
                errorMessage = buildString {
                    append("vpn:// imports are not supported")
                    if (protocol.isNotBlank() || serviceType.isNotBlank()) {
                        append(": ")
                        append(listOf(protocol, serviceType).filter { it.isNotBlank() }.joinToString(" / "))
                    }
                    append(". Use a normal subscription URL or add VLESS locations manually.")
                },
            )
        }.getOrElse {
            UnsupportedRemoteSource(
                preview = RemoteSourcePreview(
                    kindLabel = "VPN import link",
                    title = "Unreadable VPN import link",
                    detail = "The import payload could not be decoded",
                    supported = false,
                    warning = "vpn:// imports are not supported. Use a normal subscription URL or add VLESS locations manually.",
                ),
                errorMessage = "vpn:// imports are not supported. Use a normal subscription URL or add VLESS locations manually.",
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

    private data class UnsupportedRemoteSource(
        override val preview: RemoteSourcePreview,
        val errorMessage: String,
    ) : ParsedRemoteSource
}
