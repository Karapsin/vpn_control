package com.kardinal.vpncontrol.model

import kotlin.math.roundToInt

const val ALL_SUBSCRIPTIONS_ID = "__all_subscriptions__"
const val MIN_SUBSCRIPTION_REFRESH_MINUTES = 5
const val DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS = 3.0

fun AppLanguage.effective(systemLanguageCode: String?): AppLanguage {
    return if (this == AppLanguage.SYSTEM) {
        AppLanguage.fromSystemLanguageCode(systemLanguageCode)
    } else {
        this
    }
}

private const val SUBSCRIPTION_REFRESH_HOURS_SCALE = 10_000

fun normalizeSubscriptionRefreshCustomHours(hours: Double): Double {
    val sanitized = if (hours.isFinite()) hours else DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS
    return maxOf(sanitized, MIN_SUBSCRIPTION_REFRESH_MINUTES / 60.0)
}

fun subscriptionRefreshIntervalMinutes(hours: Double): Int {
    return maxOf(
        (normalizeSubscriptionRefreshCustomHours(hours) * 60.0).roundToInt(),
        MIN_SUBSCRIPTION_REFRESH_MINUTES,
    )
}

fun formatSubscriptionRefreshHoursInput(hours: Double): String {
    val scaled = (normalizeSubscriptionRefreshCustomHours(hours) * SUBSCRIPTION_REFRESH_HOURS_SCALE)
        .roundToInt()
    val whole = scaled / SUBSCRIPTION_REFRESH_HOURS_SCALE
    val fraction = (scaled % SUBSCRIPTION_REFRESH_HOURS_SCALE)
        .toString()
        .padStart(4, '0')
        .trimEnd('0')
    return if (fraction.isEmpty()) {
        whole.toString()
    } else {
        "$whole.$fraction"
    }
}

private fun formatSubscriptionRefreshInterval(minutes: Int): String {
    val normalizedMinutes = maxOf(minutes, MIN_SUBSCRIPTION_REFRESH_MINUTES)
    val hours = normalizedMinutes / 60
    val remainingMinutes = normalizedMinutes % 60
    return when {
        normalizedMinutes < 60 -> "Every $normalizedMinutes minute" +
            if (normalizedMinutes == 1) "" else "s"
        remainingMinutes == 0 -> "Every $hours hour" +
            if (hours == 1) "" else "s"
        else -> "Every ${hours} h ${remainingMinutes} min"
    }
}

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
    SOCKS,
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

    fun effectiveIntervalMinutes(customIntervalHours: Double): Long? {
        return when (this) {
            OFF -> null
            EVERY_HOUR -> 60L
            CUSTOM -> subscriptionRefreshIntervalMinutes(customIntervalHours).toLong()
        }
    }

    fun displayValue(customIntervalHours: Double): String {
        return when (this) {
            OFF -> title
            EVERY_HOUR -> title
            CUSTOM -> formatSubscriptionRefreshInterval(
                subscriptionRefreshIntervalMinutes(customIntervalHours),
            )
        }
    }
}

data class ProxyProfile(
    val protocol: ProxyProtocol = ProxyProtocol.VLESS,
    val remarks: String,
    val server: String,
    val serverPort: Int,
    val uuid: String = "",
    val username: String = "",
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

@Deprecated("Use ProxyProfile for protocol-agnostic code.", ReplaceWith("ProxyProfile"))
typealias VlessProfile = ProxyProfile

data class ProfileBenchmark(
    val profile: ProxyProfile,
    val primaryStatus: String,
    val secondaryStatus: String,
    val primaryTotal: Double?,
    val secondaryTotal: Double?,
    val score: Double,
    val detail: String,
)

data class ProfileSelection(
    val profile: ProxyProfile,
    val benchmark: ProfileBenchmark,
    val runtimeConfigJson: String,
    val sourceUrl: String = "",
)

data class SubscriptionSource(
    val id: String,
    val url: String,
    val customName: String = "",
    val cachedLocations: List<String> = emptyList(),
    val lastRefreshedAtEpochMillis: Long = 0L,
    val lastRefreshStatus: String = "",
)

data class ProfileTrafficTotal(
    val profileKey: String,
    val profileName: String,
    val sourceUrl: String = "",
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val lastUpdatedAtEpochMillis: Long = 0L,
)

data class LatencyHistoryEntry(
    val id: String,
    val profileName: String,
    val detail: String,
    val primaryStatus: String,
    val secondaryStatus: String,
    val primaryTotalMs: Double? = null,
    val secondaryTotalMs: Double? = null,
    val createdAtEpochMillis: Long = 0L,
)

data class ConnectionLogEntry(
    val id: String,
    val message: String,
    val createdAtEpochMillis: Long = 0L,
)

enum class StatusMessageKey {
    IDLE,
    LANGUAGE_SET,
    SUBSCRIPTION_AUTO_REFRESH_SET,
    VALIDATION_SETTINGS_SAVED,
    CUSTOM_DNS_SAVED,
    CUSTOM_DNS_DISABLED,
    FIND_BEST_FROM_SUBSCRIPTION,
    FIND_BEST_FROM_SAVED,
    STARTING_CONNECTION,
    STARTING_CONNECTION_WITH_BEST,
    CONNECTION_STARTED,
    CONNECTION_STOPPED,
    CONNECTION_READY_ON_COMPUTER,
    DESKTOP_APP_INITIALIZED,
    RUNTIME_MODE,
    LOCAL_PROXY,
    RUNTIME_LOG,
    PREFLIGHT_PASSED,
    PREFLIGHT_FAILED,
    DESKTOP_VPN_CAPABILITY_READY,
    DESKTOP_VPN_CAPABILITY_ERROR,
    NO_LOCATIONS_AVAILABLE_FOR_BENCHMARKING,
    BEST_LOCATION_SEARCH_TIMED_OUT,
    NO_SUITABLE_LOCATION_FOUND,
    BEST_LOCATION_NOT_MAPPED,
    ACTIVATED_ALL_SUBSCRIPTIONS,
    ACTIVATED_SUBSCRIPTION,
    PROFILE_SOURCE_MODE,
    SUBSCRIPTION_NAME_RESET,
    SUBSCRIPTION_NAME_SAVED,
    SUBSCRIPTION_DELETED,
    SELECT_LOCATION_FIRST,
    CHECKING_LOCATION,
    TESTING_LOCATION,
    LOCATION_CHECK_CANCELLED,
    NO_LOCATIONS_TO_EXPORT,
    START_ON_LOGIN_ENABLED,
    START_ON_LOGIN_DISABLED,
    STARTUP_SETTING_UPDATE_FAILED,
    SUBSCRIPTION_HWID_CLEARED,
    SUBSCRIPTION_HWID_SAVED,
    REFRESH_SETTINGS_SAVE_FAILED,
    APP_MODE_CHANGED,
    CONNECTION_STOPPED_FOR_APP_MODE,
    PREVIOUS_CONNECTION_RESTORE_PENDING,
    PREVIOUS_LOCATION_UNAVAILABLE,
    RESTORING_PREVIOUS_CONNECTION,
    CONNECTION_STARTED_ON_TARGET,
    CONNECTION_START_FAILED,
    CONNECTION_STOP_FAILED,
    APP_CLOSED_CONNECTION_WAS_OFF,
    CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH,
    CONNECTION_STOP_BEFORE_EXIT_FAILED,
}

data class StructuredStatusMessage(
    val key: StatusMessageKey,
    val args: List<String> = emptyList(),
)

object StatusMessages {
    private const val PREFIX = "vpn-control-status:v1:"

    fun encode(
        key: StatusMessageKey,
        vararg args: String,
    ): String = buildString {
        append(PREFIX)
        append(key.name)
        if (args.isNotEmpty()) {
            append(':')
            append(args.joinToString(separator = "|", transform = ::escapeArg))
        }
    }

    fun decode(raw: String): StructuredStatusMessage? {
        if (!raw.startsWith(PREFIX)) return null
        val payload = raw.removePrefix(PREFIX)
        val keyName = payload.substringBefore(':')
        val key = StatusMessageKey.entries.firstOrNull { it.name == keyName } ?: return null
        val encodedArgs = payload.substringAfter(':', missingDelimiterValue = "")
        val args = if (encodedArgs.isBlank()) {
            emptyList()
        } else {
            encodedArgs.split('|').map(::unescapeArg)
        }
        return StructuredStatusMessage(key, args)
    }

    fun idle(): String = encode(StatusMessageKey.IDLE)

    fun languageSet(languageName: String): String =
        encode(StatusMessageKey.LANGUAGE_SET, languageName)

    fun subscriptionAutoRefreshSet(
        policy: SubscriptionRefreshPolicy,
        customIntervalHours: Double,
    ): String = encode(
        StatusMessageKey.SUBSCRIPTION_AUTO_REFRESH_SET,
        policy.name,
        policy.effectiveIntervalMinutes(customIntervalHours)?.toString().orEmpty(),
    )

    fun validationSettingsSaved(settings: BenchmarkValidationSettings): String {
        val normalized = settings.normalized()
        return encode(
            StatusMessageKey.VALIDATION_SETTINGS_SAVED,
            normalized.primaryUrl.displayHost(),
            normalized.secondaryUrl.displayHost(),
            normalized.batchSize.toString(),
            normalized.retryCount.toString(),
        )
    }

    fun customDnsSaved(enabled: Boolean): String =
        encode(if (enabled) StatusMessageKey.CUSTOM_DNS_SAVED else StatusMessageKey.CUSTOM_DNS_DISABLED)

    fun findBestStart(sourceMode: ProfileSourceMode): String =
        encode(
            when (sourceMode) {
                ProfileSourceMode.SUBSCRIPTION -> StatusMessageKey.FIND_BEST_FROM_SUBSCRIPTION
                ProfileSourceMode.CURRENT_LOCATIONS -> StatusMessageKey.FIND_BEST_FROM_SAVED
            },
        )

    fun startingConnection(appMode: AppMode): String =
        encode(StatusMessageKey.STARTING_CONNECTION, appMode.name)

    fun startingConnectionWithBestLocation(appMode: AppMode): String =
        encode(StatusMessageKey.STARTING_CONNECTION_WITH_BEST, appMode.name)

    fun connectionStarted(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STARTED, appMode.name)

    fun connectionStopped(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOPPED, appMode.name)

    fun connectionReadyOnComputer(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_READY_ON_COMPUTER, appMode.name)

    fun desktopAppInitialized(): String =
        encode(StatusMessageKey.DESKTOP_APP_INITIALIZED)

    fun runtimeMode(mode: String): String =
        encode(StatusMessageKey.RUNTIME_MODE, mode)

    fun localProxy(address: String): String =
        encode(StatusMessageKey.LOCAL_PROXY, address)

    fun runtimeLog(path: String): String =
        encode(StatusMessageKey.RUNTIME_LOG, path)

    fun preflightPassed(appMode: AppMode): String =
        encode(StatusMessageKey.PREFLIGHT_PASSED, appMode.name)

    fun preflightFailed(appMode: AppMode, failedChecks: Int): String =
        encode(StatusMessageKey.PREFLIGHT_FAILED, appMode.name, failedChecks.toString())

    fun desktopVpnCapabilityReady(): String =
        encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY)

    fun desktopVpnCapabilityError(detail: String): String =
        encode(StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR, detail)

    fun noLocationsAvailableForBenchmarking(): String =
        encode(StatusMessageKey.NO_LOCATIONS_AVAILABLE_FOR_BENCHMARKING)

    fun bestLocationSearchTimedOut(): String =
        encode(StatusMessageKey.BEST_LOCATION_SEARCH_TIMED_OUT)

    fun noSuitableLocationFound(): String =
        encode(StatusMessageKey.NO_SUITABLE_LOCATION_FOUND)

    fun bestLocationNotMapped(): String =
        encode(StatusMessageKey.BEST_LOCATION_NOT_MAPPED)

    fun activatedAllSubscriptions(): String =
        encode(StatusMessageKey.ACTIVATED_ALL_SUBSCRIPTIONS)

    fun activatedSubscription(label: String): String =
        encode(StatusMessageKey.ACTIVATED_SUBSCRIPTION, label)

    fun profileSourceMode(mode: ProfileSourceMode): String =
        encode(StatusMessageKey.PROFILE_SOURCE_MODE, mode.name)

    fun subscriptionNameReset(): String =
        encode(StatusMessageKey.SUBSCRIPTION_NAME_RESET)

    fun subscriptionNameSaved(): String =
        encode(StatusMessageKey.SUBSCRIPTION_NAME_SAVED)

    fun subscriptionDeleted(): String =
        encode(StatusMessageKey.SUBSCRIPTION_DELETED)

    fun selectLocationFirst(): String =
        encode(StatusMessageKey.SELECT_LOCATION_FIRST)

    fun checkingLocation(remarks: String): String =
        encode(StatusMessageKey.CHECKING_LOCATION, remarks)

    fun testingLocation(remarks: String): String =
        encode(StatusMessageKey.TESTING_LOCATION, remarks)

    fun locationCheckCancelled(): String =
        encode(StatusMessageKey.LOCATION_CHECK_CANCELLED)

    fun noLocationsToExport(): String =
        encode(StatusMessageKey.NO_LOCATIONS_TO_EXPORT)

    fun startOnLoginEnabled(): String =
        encode(StatusMessageKey.START_ON_LOGIN_ENABLED)

    fun startOnLoginDisabled(): String =
        encode(StatusMessageKey.START_ON_LOGIN_DISABLED)

    fun startupSettingUpdateFailed(detail: String = ""): String =
        encode(StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED, detail)

    fun subscriptionHwidCleared(): String =
        encode(StatusMessageKey.SUBSCRIPTION_HWID_CLEARED)

    fun subscriptionHwidSaved(): String =
        encode(StatusMessageKey.SUBSCRIPTION_HWID_SAVED)

    fun refreshSettingsSaveFailed(detail: String = ""): String =
        encode(StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED, detail)

    fun appModeChanged(mode: AppMode): String =
        encode(StatusMessageKey.APP_MODE_CHANGED, mode.name)

    fun connectionStoppedForAppMode(
        stoppedMode: AppMode,
        nextMode: AppMode,
    ): String = encode(StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE, stoppedMode.name, nextMode.name)

    fun previousConnectionRestorePending(): String =
        encode(StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_PENDING)

    fun previousLocationUnavailable(): String =
        encode(StatusMessageKey.PREVIOUS_LOCATION_UNAVAILABLE)

    fun restoringPreviousConnection(locationName: String): String =
        encode(StatusMessageKey.RESTORING_PREVIOUS_CONNECTION, locationName)

    fun connectionStartedOnTarget(appMode: AppMode, target: String): String =
        encode(StatusMessageKey.CONNECTION_STARTED_ON_TARGET, appMode.name, target)

    fun connectionStartFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_START_FAILED, appMode.name)

    fun connectionStopFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOP_FAILED, appMode.name)

    fun appClosedConnectionWasOff(): String =
        encode(StatusMessageKey.APP_CLOSED_CONNECTION_WAS_OFF)

    fun connectionStoppedReconnectOnNextLaunch(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH, appMode.name)

    fun connectionStopBeforeExitFailed(appMode: AppMode): String =
        encode(StatusMessageKey.CONNECTION_STOP_BEFORE_EXIT_FAILED, appMode.name)

    private fun escapeArg(value: String): String = buildString {
        value.forEach { char ->
            when (char) {
                '%' -> append("%25")
                '|' -> append("%7C")
                ':' -> append("%3A")
                '\n' -> append("%0A")
                '\r' -> append("%0D")
                else -> append(char)
            }
        }
    }

    private fun unescapeArg(value: String): String {
        val builder = StringBuilder()
        var index = 0
        while (index < value.length) {
            if (value[index] == '%' && index + 2 < value.length) {
                when (value.substring(index + 1, index + 3)) {
                    "25" -> {
                        builder.append('%')
                        index += 3
                        continue
                    }
                    "7C" -> {
                        builder.append('|')
                        index += 3
                        continue
                    }
                    "3A" -> {
                        builder.append(':')
                        index += 3
                        continue
                    }
                    "0A" -> {
                        builder.append('\n')
                        index += 3
                        continue
                    }
                    "0D" -> {
                        builder.append('\r')
                        index += 3
                        continue
                    }
                }
            }
            builder.append(value[index])
            index += 1
        }
        return builder.toString()
    }
}

data class PersistedState(
    val appLanguage: AppLanguage = AppLanguage.SYSTEM,
    val subscriptionHwid: String = "",
    val profileUrl: String = "",
    val activeSubscriptionId: String = "",
    val subscriptions: List<SubscriptionSource> = emptyList(),
    val profileHistory: List<String> = emptyList(),
    val profileHistoryNames: Map<String, String> = emptyMap(),
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val appMode: AppMode = AppMode.VPN,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val findBestAfterSubscriptionRefresh: Boolean = true,
    val subscriptionRefreshCustomHours: Double = DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS,
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
    val liveTrafficStatsEnabled: Boolean = false,
    val profileTotalsEnabled: Boolean = false,
    val latencyHistoryEnabled: Boolean = false,
    val connectionLogEnabled: Boolean = false,
    val connectionTestToolsEnabled: Boolean = false,
    val sessionStartedAtEpochMillis: Long = 0L,
    val sessionStoppedAtEpochMillis: Long = 0L,
    val sessionStartRxBytes: Long = -1L,
    val sessionStartTxBytes: Long = -1L,
    val successfulStarts: Int = 0,
    val successfulStops: Int = 0,
    val profileTrafficTotals: List<ProfileTrafficTotal> = emptyList(),
    val latencyHistory: List<LatencyHistoryEntry> = emptyList(),
    val connectionLog: List<ConnectionLogEntry> = emptyList(),
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
            val parsed = parseHttpUrl(raw) ?: return fallback
            return buildString {
                append("https://")
                append(parsed.host)
                parsed.port?.let {
                    append(':')
                    append(it)
                }
                append(parsed.path)
                parsed.query?.let {
                    append('?')
                    append(it)
                }
                parsed.fragment?.let {
                    append('#')
                    append(it)
                }
            }
        }
    }
}

fun supportsAllSubscriptionsGroup(subscriptions: List<SubscriptionSource>): Boolean =
    subscriptions.size > 1

fun isAllSubscriptionsGroupActive(
    activeSubscriptionId: String,
    subscriptions: List<SubscriptionSource>,
): Boolean = activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && supportsAllSubscriptionsGroup(subscriptions)

fun mergedSubscriptionLocations(subscriptions: List<SubscriptionSource>): List<String> =
    buildList {
        val seen = linkedSetOf<String>()
        subscriptions.forEach { subscription ->
            subscription.cachedLocations.forEach { rawLink ->
                if (seen.add(rawLink)) {
                    add(rawLink)
                }
            }
        }
    }

fun activeSubscriptionUrls(
    activeSubscriptionId: String,
    subscriptions: List<SubscriptionSource>,
): Set<String> = when {
    isAllSubscriptionsGroupActive(activeSubscriptionId, subscriptions) ->
        subscriptions.mapNotNull { it.url.takeIf(String::isNotBlank) }.toSet()
    else ->
        subscriptions.firstOrNull { it.id == activeSubscriptionId }
            ?.url
            ?.takeIf(String::isNotBlank)
            ?.let(::setOf)
            .orEmpty()
}

fun sourceUrlForStoredLocation(
    subscriptions: List<SubscriptionSource>,
    storedLocation: String,
): String = subscriptions
    .firstOrNull { storedLocation in it.cachedLocations }
    ?.url
    .orEmpty()

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
                        .lowercase()
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
                        .lowercase()
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
                .lowercase()
            return normalized.takeIf { it.isNotBlank() }?.let { ".$it" }
        }
    }
}

data class InstalledApp(
    val packageName: String,
    val label: String,
    val isSystemApp: Boolean,
)

private data class ParsedHttpUrl(
    val host: String,
    val port: Int?,
    val path: String,
    val query: String?,
    val fragment: String?,
)

private fun parseHttpUrl(raw: String): ParsedHttpUrl? {
    val trimmed = raw.trim()
    if (trimmed.isBlank()) return null
    val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
    val schemeSeparatorIndex = withScheme.indexOf("://")
    if (schemeSeparatorIndex <= 0) return null
    val scheme = withScheme.substring(0, schemeSeparatorIndex).lowercase()
    if (scheme != "https" && scheme != "http") return null

    val remainder = withScheme.substring(schemeSeparatorIndex + 3)
    if (remainder.isBlank()) return null

    val authorityEndIndex = remainder.indexOfFirst { it == '/' || it == '?' || it == '#' }
    val authority = if (authorityEndIndex == -1) remainder else remainder.substring(0, authorityEndIndex)
    if (authority.isBlank()) return null
    val suffix = if (authorityEndIndex == -1) "" else remainder.substring(authorityEndIndex)

    val hostAndPort = parseHostAndPort(authority) ?: return null
    val pathEndIndex = suffix.indexOfFirst { it == '?' || it == '#' }.let { index ->
        if (index == -1) suffix.length else index
    }
    val path = suffix.substring(0, pathEndIndex).ifBlank { "" }
    val queryStartIndex = suffix.indexOf('?')
    val fragmentStartIndex = suffix.indexOf('#')
    val query = if (queryStartIndex == -1) {
        null
    } else {
        val queryEndIndex = if (fragmentStartIndex == -1 || fragmentStartIndex < queryStartIndex) {
            suffix.length
        } else {
            fragmentStartIndex
        }
        suffix.substring(queryStartIndex + 1, queryEndIndex).takeIf { it.isNotEmpty() }
    }
    val fragment = if (fragmentStartIndex == -1) {
        null
    } else {
        suffix.substring(fragmentStartIndex + 1).takeIf { it.isNotEmpty() }
    }

    return ParsedHttpUrl(
        host = hostAndPort.first,
        port = hostAndPort.second,
        path = path,
        query = query,
        fragment = fragment,
    )
}

private fun parseHostAndPort(authority: String): Pair<String, Int?>? {
    if (authority.startsWith('[')) {
        val endIndex = authority.indexOf(']')
        if (endIndex <= 0) return null
        val host = authority.substring(0, endIndex + 1)
        val port = authority.substring(endIndex + 1)
            .removePrefix(":")
            .takeIf { it.isNotBlank() }
            ?.toIntOrNull()
        return host.takeIf { it.isNotBlank() }?.let { it to port }
    }

    val lastColonIndex = authority.lastIndexOf(':')
    if (lastColonIndex > 0 && authority.indexOf(':') == lastColonIndex) {
        val portValue = authority.substring(lastColonIndex + 1).toIntOrNull()
        if (portValue != null) {
            val host = authority.substring(0, lastColonIndex)
            return host.takeIf { it.isNotBlank() }?.let { it to portValue }
        }
    }

    return authority.takeIf { it.isNotBlank() }?.let { it to null }
}

private fun String.displayHost(): String {
    return parseHttpUrl(this)
        ?.host
        ?.removePrefix("www.")
        ?.takeIf { it.isNotBlank() }
        ?: this
}
