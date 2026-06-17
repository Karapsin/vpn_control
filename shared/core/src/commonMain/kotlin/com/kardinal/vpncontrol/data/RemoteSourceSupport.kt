package com.kardinal.vpncontrol.data

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

sealed interface DirectRemoteSourceParseResult {
    val preview: RemoteSourcePreview
}

data class DirectRemoteSourceResolution(
    val url: String,
    override val preview: RemoteSourcePreview,
) : DirectRemoteSourceParseResult

data class UnsupportedRemoteSourceResolution(
    override val preview: RemoteSourcePreview,
    val errorMessage: String,
) : DirectRemoteSourceParseResult

fun parseDirectRemoteSource(raw: String): DirectRemoteSourceParseResult? {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) return null
    return when {
        trimmed.startsWith("http://", ignoreCase = true) -> {
            UnsupportedRemoteSourceResolution(
                preview = RemoteSourcePreview(
                    kindLabel = "Subscription URL",
                    title = displayRemoteSourceHost(trimmed) ?: trimmed,
                    detail = "Insecure HTTP subscriptions are not supported",
                    supported = false,
                    warning = "Use an https:// subscription URL.",
                ),
                errorMessage = "HTTP subscription URLs are not supported. Use https:// instead.",
            )
        }
        trimmed.startsWith("https://", ignoreCase = true) -> {
            val host = displayRemoteSourceHost(trimmed)
            if (host.isNullOrBlank()) {
                UnsupportedRemoteSourceResolution(
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
                DirectRemoteSourceResolution(
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
        else -> null
    }
}

fun redactRemoteSourceUrl(raw: String): String {
    val parsed = parseSimpleUrl(raw.trim()) ?: return raw
    return buildString {
        append(parsed.scheme)
        append("://")
        append(parsed.authority)
        append("/<redacted>")
    }
}

fun displayRemoteSourceHost(raw: String): String? {
    return parseSimpleUrl(raw.trim())
        ?.host
        ?.removePrefix("www.")
        ?.takeIf { it.isNotBlank() }
}

private data class ParsedSimpleUrl(
    val scheme: String,
    val authority: String,
    val host: String,
)

private fun parseSimpleUrl(raw: String): ParsedSimpleUrl? {
    val schemeSplit = raw.indexOf("://")
    if (schemeSplit <= 0) return null
    val scheme = raw.substring(0, schemeSplit).lowercase()
    val remainder = raw.substring(schemeSplit + 3)
    if (remainder.isBlank()) return null

    val authorityEnd = remainder.indexOfAny(charArrayOf('/', '?', '#')).let { idx ->
        if (idx == -1) remainder.length else idx
    }
    val authorityRaw = remainder.substring(0, authorityEnd)
    if (authorityRaw.isBlank()) return null
    val authority = authorityRaw.substringAfterLast('@')
    val host = extractHost(authority) ?: return null
    return ParsedSimpleUrl(
        scheme = scheme,
        authority = authority,
        host = host,
    )
}

private fun extractHost(authority: String): String? {
    if (authority.isBlank()) return null
    return when {
        authority.startsWith("[") -> authority.substringAfter("[").substringBefore("]").takeIf { it.isNotBlank() }
        authority.count { it == ':' } == 1 -> authority.substringBefore(':').takeIf { it.isNotBlank() }
        else -> authority.takeIf { it.isNotBlank() }
    }
}
