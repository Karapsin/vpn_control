package com.kardinal.vpncontrol.model

import java.net.URI
import java.util.Locale

enum class ProfileSourceMode {
    SUBSCRIPTION,
    CURRENT_LOCATIONS,
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

data class VlessProfile(
    val remarks: String,
    val uuid: String,
    val server: String,
    val serverPort: Int,
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
    val rawLink: String,
)

data class ProfileBenchmark(
    val profile: VlessProfile,
    val googleStatus: String,
    val chatgptStatus: String,
    val googleTotal: Double?,
    val chatgptTotal: Double?,
    val score: Double,
    val detail: String,
)

data class ProfileSelection(
    val profile: VlessProfile,
    val benchmark: ProfileBenchmark,
    val runtimeConfigJson: String,
)

data class PersistedState(
    val profileUrl: String = "",
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshCustomHours: Int = 3,
    val validationSettings: BenchmarkValidationSettings = BenchmarkValidationSettings(),
    val currentLocations: List<String> = emptyList(),
    val locationBenchmarkDetails: Map<String, String> = emptyMap(),
    val customDns: String = "",
    val useCustomDns: Boolean = false,
    val routingRules: RoutingRules = RoutingRules(),
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val selectedProfileRawLink: String = "",
    val selectedProfileJson: String = "",
    val lastBenchmarkSummary: String = "",
    val runtimeConfigJson: String = "",
    val statusMessage: String = "Idle",
    val isVpnRunning: Boolean = false,
)

data class BenchmarkValidationSettings(
    val generalUrl: String = DEFAULT_GENERAL_URL,
    val chatGptUrl: String = DEFAULT_CHATGPT_URL,
    val candidateCount: Int = DEFAULT_CANDIDATE_COUNT,
) {
    fun normalized(): BenchmarkValidationSettings {
        return copy(
            generalUrl = normalizeUrl(generalUrl, DEFAULT_GENERAL_URL),
            chatGptUrl = normalizeUrl(chatGptUrl, DEFAULT_CHATGPT_URL),
            candidateCount = candidateCount.coerceAtLeast(1),
        )
    }

    fun concurrency(): Int = normalized().candidateCount.coerceAtMost(5)

    fun displaySummary(): String {
        val normalized = normalized()
        return "${normalized.generalUrl.displayHost()} • " +
            "${normalized.chatGptUrl.displayHost()} • " +
            "top ${normalized.candidateCount} • conc ${normalized.concurrency()}"
    }

    companion object {
        const val DEFAULT_GENERAL_URL = "https://www.google.com/generate_204"
        const val DEFAULT_CHATGPT_URL = "https://chatgpt.com/"
        const val DEFAULT_CANDIDATE_COUNT = 3

        private fun normalizeUrl(raw: String, fallback: String): String {
            val trimmed = raw.trim()
            if (trimmed.isBlank()) return fallback
            return if (trimmed.contains("://")) trimmed else "https://$trimmed"
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

data class RoutingRules(
    val ignoreRules: Boolean = false,
    val proxyPackages: List<String> = emptyList(),
    val bypassPackages: List<String> = emptyList(),
    val nationalDomainSuffixes: List<String> = DEFAULT_NATIONAL_DOMAIN_SUFFIXES,
    val directDomainSuffixes: List<String> = DEFAULT_DIRECT_DOMAIN_SUFFIXES,
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
