package com.kardinal.vpncontrol.data

internal fun looksLikeRemoteSourceLink(raw: String): Boolean {
    val trimmed = raw.trim()
    return trimmed.startsWith("http://", ignoreCase = true) ||
        trimmed.startsWith("https://", ignoreCase = true) ||
        trimmed.startsWith("sing-box://import-remote-profile", ignoreCase = true) ||
        trimmed.startsWith("vpn://", ignoreCase = true)
}

internal fun isUnsupportedVpnImport(raw: String): Boolean {
    return raw.trim().startsWith("vpn://", ignoreCase = true)
}

internal fun looksLikeProxyLink(raw: String): Boolean {
    val normalized = raw.trim().lowercase()
    return normalized.startsWith("vless://") ||
        normalized.startsWith("trojan://") ||
        normalized.startsWith("ss://") ||
        normalized.startsWith("vmess://") ||
        normalized.startsWith("socks://")
}
