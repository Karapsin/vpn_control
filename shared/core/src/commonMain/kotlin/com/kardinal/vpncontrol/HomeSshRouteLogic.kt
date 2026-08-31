package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.HomeSshRouteSettings

enum class SubscriptionDownloadRoute {
    ACTIVE_SESSION,
    HOME_RELAY,
    DIRECT,
}

data class SubscriptionDownloadRoutePlan(
    val primary: SubscriptionDownloadRoute,
    val transportFailureFallback: SubscriptionDownloadRoute? = null,
)

object SubscriptionDownloadRouteLogic {
    fun plan(
        runtimeIsActive: Boolean,
        homeRouteEnabled: Boolean,
    ): SubscriptionDownloadRoutePlan {
        if (runtimeIsActive) {
            return SubscriptionDownloadRoutePlan(
                primary = SubscriptionDownloadRoute.ACTIVE_SESSION,
                transportFailureFallback = if (homeRouteEnabled) SubscriptionDownloadRoute.HOME_RELAY else null,
            )
        }
        return SubscriptionDownloadRoutePlan(
            primary = if (homeRouteEnabled) SubscriptionDownloadRoute.HOME_RELAY else SubscriptionDownloadRoute.DIRECT,
        )
    }
}

object HomeSshRouteLogic {
    fun fromDraft(state: MainUiState): Result<HomeSshRouteSettings> = runCatching {
        HomeSshRouteSettings(
            enabled = state.homeSshEnabledDraft,
            host = state.homeSshHostDraft,
            port = state.homeSshPortDraft.trim().toIntOrNull()
                ?: error("SSH port must be a number"),
            user = state.homeSshUserDraft,
            hostKeys = state.homeSshHostKeysDraft.lineSequence().toList(),
            relayPort = state.homeSshRelayPortDraft.trim().toIntOrNull()
                ?: error("Home relay port must be a number"),
            credentialVersion = state.homeSshRouteSettings.credentialVersion,
        )
    }

    fun normalize(settings: HomeSshRouteSettings): HomeSshRouteSettings {
        val normalizedHost = settings.host.trim().removePrefix("ssh://").trimEnd('/').let { host ->
            if (host.startsWith('[') && host.endsWith(']')) host.substring(1, host.length - 1) else host
        }
        return settings.copy(
            host = normalizedHost,
            user = settings.user.trim(),
            hostKeys = settings.hostKeys.mapNotNull(::normalizeHostKey).distinct(),
        )
    }

    fun validate(settings: HomeSshRouteSettings, credentialAvailable: Boolean): Result<HomeSshRouteSettings> = runCatching {
        val suppliedHostKeys = settings.hostKeys.map(String::trim).filter(String::isNotBlank)
        if (settings.enabled) {
            require(suppliedHostKeys.isNotEmpty()) { "A pinned SSH host key is required" }
            require(suppliedHostKeys.all { normalizeHostKey(it) != null }) {
                "Every pinned SSH host key must contain a supported algorithm and base64 public key"
            }
        }
        val normalized = normalize(settings)
        if (!normalized.enabled) return@runCatching normalized
        require(normalized.host.isNotBlank()) { "SSH host is required" }
        require(!normalized.host.any(Char::isWhitespace)) { "SSH host must not contain whitespace" }
        require(normalized.host.none { it == '/' || it == '@' || it == '?' || it == '#' }) {
            "SSH host must be a hostname or IP address without a scheme, user, or path"
        }
        require('[' !in normalized.host && ']' !in normalized.host) { "SSH host contains invalid IPv6 brackets" }
        require(normalized.host.count { it == ':' } != 1) {
            "Enter the SSH port in the separate port field"
        }
        require(normalized.port in 1..65535) { "SSH port must be between 1 and 65535" }
        require(normalized.user.isNotBlank()) { "SSH user is required" }
        require(!normalized.user.any(Char::isWhitespace)) { "SSH user must not contain whitespace" }
        require(normalized.relayPort in 1..65535) { "Home relay port must be between 1 and 65535" }
        require(credentialAvailable) { "An SSH private key must be imported" }
        normalized
    }

    fun runtimeFingerprint(settings: HomeSshRouteSettings): String {
        val normalized = normalize(settings)
        return listOf(
            normalized.enabled,
            normalized.host,
            normalized.port,
            normalized.user,
            normalized.relayPort,
            normalized.hostKeys.joinToString("|"),
            normalized.credentialVersion,
        ).joinToString(";")
    }

    private fun normalizeHostKey(raw: String): String? {
        val fields = raw.trim().split(Regex("\\s+")).filter(String::isNotBlank)
        if (fields.size < 2) return null
        val algorithmIndex = fields.indexOfFirst { field ->
            field.startsWith("ssh-") || field.startsWith("ecdsa-") || field.startsWith("sk-")
        }
        if (algorithmIndex < 0 || algorithmIndex + 1 >= fields.size) return null
        val algorithm = fields[algorithmIndex]
        val encoded = fields[algorithmIndex + 1]
        if (algorithm !in supportedHostKeyAlgorithms) return null
        if (!encoded.matches(base64KeyRegex) || encoded.length < 16) return null
        return "$algorithm $encoded"
    }

    private val supportedHostKeyAlgorithms = setOf(
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    )
    private val base64KeyRegex = Regex("^[A-Za-z0-9+/]+={0,2}$")
}
