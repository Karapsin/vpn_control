package com.kardinal.vpncontrol.model

import java.net.URI
import java.util.Locale

enum class ProfileSourceMode {
    SUBSCRIPTION,
    CURRENT_LOCATIONS,
}

enum class AppMode {
    VPN,
    PROXY_ONLY,
}

enum class ProxyProtocol {
    VLESS,
    TROJAN,
    SHADOWSOCKS,
    VMESS,
    CUSTOM,
}

enum class RoutingRuleSetSourceType {
    INLINE,
    REMOTE,
}

enum class RoutingRuleSetFormat {
    SOURCE,
    BINARY,
}

enum class RoutingRuleSetAction {
    DIRECT,
    PROXY,
    BLOCK,
}

enum class SubscriptionRefreshPolicy(
    val title: String,
) {
    OFF(title = "Off"),
    EVERY_HOUR(title = "Every hour"),
    CUSTOM(title = "Custom interval");

    fun effectiveIntervalHours(customIntervalHours: Int): Long? {
        return when (this) {
            OFF -> null
            EVERY_HOUR -> 1L
            CUSTOM -> customIntervalHours.coerceAtLeast(1).toLong()
        }
    }

    fun displayValue(customIntervalHours: Int): String {
        return when (this) {
            OFF -> title
            EVERY_HOUR -> title
            CUSTOM -> "Every ${customIntervalHours.coerceAtLeast(1)} hour" +
                if (customIntervalHours.coerceAtLeast(1) == 1) "" else "s"
        }
    }
}

data class ProxyProfile(
    val protocol: ProxyProtocol = ProxyProtocol.VLESS,
    val remarks: String,
    val server: String,
    val serverPort: Int,
    val uuid: String = "",
    val password: String = "",
    val method: String = "",
    val network: String,
    val flow: String,
    val security: String,
    val sni: String,
    val fingerprint: String,
    val publicKey: String,
    val shortId: String,
    val path: String,
    val hostHeader: String,
    val serviceName: String,
    val headerType: String,
    val alterId: Int = 0,
    val vmessSecurity: String = "auto",
    val plugin: String = "",
    val pluginOptions: String = "",
    val rawLink: String,
    val customConfigJson: String = "",
)

typealias VlessProfile = ProxyProfile

data class ProfileBenchmark(
    val profile: VlessProfile,
    val primaryStatus: String,
    val secondaryStatus: String,
    val primaryTotal: Double?,
    val secondaryTotal: Double?,
    val score: Double,
    val detail: String,
)

data class ProfileSelection(
    val profile: VlessProfile,
    val benchmark: ProfileBenchmark,
    val runtimeConfigJson: String,
)

data class SubscriptionSource(
    val id: String,
    val url: String,
    val customName: String = "",
    val cachedLocations: List<String> = emptyList(),
    val lastRefreshedAtEpochMillis: Long = 0L,
    val lastRefreshStatus: String = "",
)

data class PersistedState(
    val profileUrl: String = "",
    val activeSubscriptionId: String = "",
    val subscriptions: List<SubscriptionSource> = emptyList(),
    val profileHistory: List<String> = emptyList(),
    val profileHistoryNames: Map<String, String> = emptyMap(),
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val appMode: AppMode = AppMode.VPN,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshCustomHours: Int = 3,
    val validationSettings: BenchmarkValidationSettings = BenchmarkValidationSettings(),
    val savedLocations: List<String> = emptyList(),
    val currentLocations: List<String> = emptyList(),
    val locationBenchmarkDetails: Map<String, String> = emptyMap(),
    val customDns: String = "",
    val useCustomDns: Boolean = false,
    val routingRules: RoutingRules = RoutingRules(),
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val selectedProfileRawLink: String = "",
    val selectedProfileJson: String = "",
    val selectedProfileSourceUrl: String = "",
    val lastBenchmarkSummary: String = "",
    val runtimeConfigJson: String = "",
    val statusMessage: String = "Idle",
    val isVpnRunning: Boolean = false,
    val sessionStatsEnabled: Boolean = false,
    val sessionStartedAtEpochMillis: Long = 0L,
    val sessionStoppedAtEpochMillis: Long = 0L,
    val successfulStarts: Int = 0,
    val successfulStops: Int = 0,
)

data class BenchmarkValidationSettings(
    val primaryUrl: String = DEFAULT_PRIMARY_URL,
    val secondaryUrl: String = DEFAULT_SECONDARY_URL,
    val batchSize: Int = DEFAULT_BATCH_SIZE,
    val retryCount: Int = DEFAULT_RETRY_COUNT,
) {
    fun normalized(): BenchmarkValidationSettings {
        return copy(
            primaryUrl = normalizeUrl(primaryUrl, DEFAULT_PRIMARY_URL),
            secondaryUrl = normalizeUrl(secondaryUrl, DEFAULT_SECONDARY_URL),
            batchSize = batchSize.coerceAtLeast(1),
            retryCount = retryCount.coerceAtLeast(0),
        )
    }

    fun displaySummary(): String {
        val normalized = normalized()
        return "${normalized.primaryUrl.displayHost()} • ${normalized.secondaryUrl.displayHost()} • batch ${normalized.batchSize} • retries ${normalized.retryCount}"
    }

    companion object {
        const val DEFAULT_PRIMARY_URL = "https://www.google.com/generate_204"
        const val DEFAULT_SECONDARY_URL = "https://chatgpt.com/"
        const val DEFAULT_BATCH_SIZE = 3
        const val DEFAULT_RETRY_COUNT = 1

        private fun normalizeUrl(raw: String, fallback: String): String {
            val trimmed = raw.trim()
            if (trimmed.isBlank()) return fallback
            val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
            val uri = runCatching { URI(withScheme) }.getOrNull() ?: return fallback
            val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return fallback
            if (scheme != "https" && scheme != "http") return fallback
            val host = uri.host?.takeIf { it.isNotBlank() } ?: return fallback
            return buildString {
                append("https://")
                append(host)
                if (uri.port != -1) {
                    append(':')
                    append(uri.port)
                }
                uri.rawPath?.takeIf { it.isNotBlank() }?.let { append(it) }
                uri.rawQuery?.let {
                    append('?')
                    append(it)
                }
                uri.rawFragment?.let {
                    append('#')
                    append(it)
                }
            }
        }

        private fun String.displayHost(): String {
            return runCatching { URI(this).host }
                .getOrNull()
                ?.removePrefix("www.")
                ?.takeIf { it.isNotBlank() }
                ?: this
        }
    }
}

data class RoutingRuleSet(
    val id: String,
    val name: String,
    val sourceType: RoutingRuleSetSourceType = RoutingRuleSetSourceType.REMOTE,
    val format: RoutingRuleSetFormat = RoutingRuleSetFormat.SOURCE,
    val action: RoutingRuleSetAction = RoutingRuleSetAction.DIRECT,
    val source: String,
    val updateIntervalHours: Int = 24,
) {
    fun normalized(): RoutingRuleSet {
        return copy(
            id = id.trim(),
            name = name.trim(),
            source = source.trim(),
            updateIntervalHours = updateIntervalHours.coerceAtLeast(1),
        )
    }
}

data class RoutingRules(
    val ignoreRules: Boolean = false,
    val proxyPackages: List<String> = emptyList(),
    val bypassPackages: List<String> = emptyList(),
    val nationalDomainSuffixes: List<String> = DEFAULT_NATIONAL_DOMAIN_SUFFIXES,
    val directDomainSuffixes: List<String> = DEFAULT_DIRECT_DOMAIN_SUFFIXES,
    val ruleSets: List<RoutingRuleSet> = emptyList(),
) {
    val allDirectDomainSuffixes: List<String>
        get() = (nationalDomainSuffixes + directDomainSuffixes)
            .mapNotNull(::toDomainSuffix)
            .distinct()

    companion object {
        val DEFAULT_NATIONAL_DOMAIN_SUFFIXES = emptyList<String>()
        val DEFAULT_DIRECT_DOMAIN_SUFFIXES = emptyList<String>()

        fun normalizePackageNames(values: Iterable<String>): List<String> {
            return values
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .distinct()
                .sorted()
        }

        fun parseNationalDomainSuffixes(input: String): List<String> {
            return tokenize(input)
                .map { suffix ->
                    suffix
                        .removePrefix("*.")
                        .trimStart('.')
                        .trimEnd('.')
                        .lowercase(Locale.ROOT)
                }
                .filter { it.isNotBlank() }
                .distinct()
        }

        fun parseDirectDomainSuffixes(input: String): List<String> {
            return tokenize(input)
                .map { suffix ->
                    suffix
                        .removePrefix("*.")
                        .trimStart('.')
                        .trimEnd('.')
                        .lowercase(Locale.ROOT)
                }
                .filter { it.isNotBlank() }
                .distinct()
        }

        private fun tokenize(input: String): List<String> {
            return input
                .split(Regex("[,\\n\\r\\t ]+"))
                .map { it.trim() }
                .filter { it.isNotBlank() }
        }

        private fun toDomainSuffix(value: String): String? {
            val normalized = value
                .removePrefix("*.")
                .trimStart('.')
                .trimEnd('.')
                .lowercase(Locale.ROOT)
            return normalized.takeIf { it.isNotBlank() }?.let { ".$it" }
        }
    }
}

data class InstalledApp(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
)
