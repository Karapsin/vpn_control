package com.kardinal.vpncontrol.shared.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.StructuredStatusMessage
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.effective
import com.kardinal.vpncontrol.model.subscriptionRefreshIntervalMinutes
import kotlinx.datetime.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

enum class UiText {
    APP_TITLE,
    TAB_MAIN,
    TAB_PROFILE,
    TAB_LOCATIONS,
    TAB_STATS,
    TAB_RULES,
    MAIN_SUBSCRIPTION_DESCRIPTION,
    MAIN_SAVED_LOCATIONS_DESCRIPTION,
    CONNECT,
    DISCONNECT,
    START_VPN,
    STOP_VPN,
    START_PROXY,
    STOP_PROXY,
    VPN_PERMISSION_REQUIRED,
    VPN_CONNECT_DESCRIPTION,
    PROXY_CONNECT_DESCRIPTION,
    FIND_BEST,
    FIND_BEST_SUBSCRIPTION,
    FIND_BEST_SAVED,
    EXPORT_DIAGNOSTICS,
    STATUS,
    SELECTED_PROFILE,
    SELECTED_LOCATION,
    SERVER,
    MISMATCH_TITLE,
    MISMATCH_ACTIVE_PROFILE,
    MISMATCH_ACTION,
    PROFILE_TITLE,
    PROFILE_DESCRIPTION,
    CURRENT_SELECTION,
    STATS_TITLE,
    STATS_DESCRIPTION,
    SESSION,
    RUNNING_FOR,
    STOPPED,
    STARTED,
    SUCCESSFUL_STARTS_STOPS,
    CONNECTION_LOG,
    NO_RECENT_EVENTS,
    NEVER,
    SETTINGS_LANGUAGE,
    ADDITIONAL_SETTINGS,
    SETTINGS_LANGUAGE_SYSTEM,
    SETTINGS_LANGUAGE_DIALOG_TITLE,
    SETTINGS_LANGUAGE_DIALOG_DESCRIPTION,
    SETTINGS_CUSTOM_DNS,
    SETTINGS_START_ON_LOGIN,
    SETTINGS_VPN_PROXY_MODE,
    SETTINGS_PROXY_MODE,
    SETTINGS_SUBSCRIPTION_REFRESH,
    SETTINGS_LOCATION_TEST,
    SETTINGS_ENABLED,
    SETTINGS_DISABLED,
    SETTINGS_VPN_MODE,
    SETTINGS_PROXY_ONLY,
    SETTINGS_ALL_SUBSCRIPTIONS,
    SETTINGS_SELECTED_SUBSCRIPTION,
    SAVE,
    CANCEL,
    CLOSE,
    OK,
    USE_CUSTOM_DNS,
    DNS_APPLIES_NEW_DESKTOP_SESSIONS,
    DNS_IP_ADDRESS,
    APP_MODE_ANDROID_DESCRIPTION,
    APP_MODE_DESKTOP_DESCRIPTION,
    VPN,
    VPN_MODE_LABEL,
    PROXY_ONLY,
    APP_MODE_ANDROID_PROXY_DETAIL,
    APP_MODE_ANDROID_VPN_DETAIL,
    APP_MODE_ANDROID_VPN_FOOTER,
    APP_MODE_DESKTOP_VPN_DETAIL,
    APP_MODE_DESKTOP_PROXY_DETAIL,
    APP_MODE_DESKTOP_CHANGE_WARNING,
    REFRESH_DESCRIPTION_ALL,
    REFRESH_DESCRIPTION_SELECTED,
    REFRESH_DESCRIPTION_DESKTOP,
    REFRESH_POLICY_OFF,
    REFRESH_POLICY_HOURLY,
    REFRESH_POLICY_CUSTOM,
    REFRESH_POLICY_OFF_DESCRIPTION,
    REFRESH_POLICY_HOURLY_DESCRIPTION,
    REFRESH_POLICY_CUSTOM_DESCRIPTION,
    FIND_BEST_AFTER_REFRESH,
    KEEP_CURRENT_LOCATION_AFTER_REFRESH,
    FIND_BEST_AFTER_REFRESH_DESCRIPTION,
    KEEP_CURRENT_LOCATION_AFTER_REFRESH_DESCRIPTION,
    CUSTOM_INTERVAL_HOURS,
    CUSTOM_INTERVAL_HELP,
    VALIDATION_DESCRIPTION_ALL,
    VALIDATION_DESCRIPTION_SELECTED,
    VALIDATION_DESCRIPTION_DESKTOP,
    PRIMARY_TEST_SITE,
    SECONDARY_TEST_SITE,
    BATCH_SIZE,
    RETRY_COUNT,
    PRIMARY_TEST_SITE_PLACEHOLDER,
    SECONDARY_TEST_SITE_PLACEHOLDER,
    VALIDATION_ANDROID_SUMMARY,
    VALIDATION_DESKTOP_SUMMARY,
    VALIDATION_SUMMARY,
    IMPORT,
    EXPORT,
    FILE,
    CLIPBOARD,
    QR,
    QR_EXPORT_TOO_LARGE,
    QR_TOO_LARGE_MESSAGE,
    EXPORT_KIND_LOCATIONS,
    EXPORT_KIND_RULES,
    QR_GENERATION_FAILED,
    BYTES_COUNT,
    LOCATIONS_EXPORT_TITLE,
    RULES_EXPORT_TITLE,
    LOCATIONS_TITLE,
    LOCATIONS_DESCRIPTION_SUBSCRIPTION,
    LOCATIONS_DESCRIPTION_SAVED,
    SAVED_LOCATIONS_COUNT,
    SELECTED_NONE,
    SELECTED_VALUE,
    ADD_LOCATION,
    NO_LOCATIONS_CACHED,
    NO_SAVED_LOCATIONS,
    INVALID_LOCATION_CONFIG,
    COULD_NOT_READ_LOCATION,
    CUSTOM_SING_BOX_CONFIG,
    TAP_EDIT_TO_FIX_LOCATION,
    IN_USE,
    SELECTED,
    STOP_CONNECTION_FOR_LOCATION,
    START_CONNECTION_FOR_LOCATION,
    SELECT_THIS_LOCATION,
    RECHECK_LOCATION,
    EDIT_LOCATION,
    DELETE_LOCATION,
    SUBSCRIPTION_NAME_TITLE,
    NAME,
    MY_SUBSCRIPTION,
    RENAME_SUBSCRIPTION_HELP,
    READ_ONLY_LOCATION_TITLE,
    LOCATION_CONFIG_LABEL,
    LOCATION_CONFIG_HELP,
    PROFILE_SOURCE,
    PROFILE_SOURCE_DESCRIPTION_SUBSCRIPTION,
    PROFILE_SOURCE_DESCRIPTION_SAVED,
    SUBSCRIPTION,
    SAVED_LOCATIONS,
    PROFILE_SOURCE_USE_SAVED_HINT,
    PROFILE_SOURCE_USE_SUBSCRIPTION_HINT,
    ADD_NEW_SUBSCRIPTION,
    CLEAR_REMOTE_SOURCE,
    CLOSE_SUBSCRIPTION_EDITOR,
    SUBSCRIPTION_URL,
    SUBSCRIPTION_URL_PLACEHOLDER,
    SUBSCRIPTION_URL_HELP,
    DESKTOP_SUBSCRIPTION_URL_HELP,
    SAVE_REMOTE_SOURCE,
    SAVE_SUBSCRIPTION,
    SUBSCRIPTIONS,
    REFRESH_ACTIVE,
    REFRESH_ALL,
    ALL_SUBSCRIPTIONS,
    ALL_SUBSCRIPTIONS_TITLE,
    ALL_SUBSCRIPTIONS_DESCRIPTION,
    ACTIVE,
    SAVED_SOURCE,
    REMOTE_SOURCE,
    DETECTED_VALUE,
    TAP_TO_USE_SOURCE,
    LAST_REFRESH,
    NOT_REFRESHED_YET,
    ACTIVE_SUBSCRIPTION,
    SELECTED_SUBSCRIPTION,
    RENAME_SUBSCRIPTION,
    DELETE_SUBSCRIPTION,
    SUBSCRIPTION_NAME,
    OPTIONAL_CUSTOM_NAME,
    DESKTOP_SHELL,
    DESKTOP_SHELL_DESCRIPTION,
    AUTO_REFRESH_WHILE_OPEN,
    SUBSCRIPTION_MODE,
    PROFILE_SOURCE_DESKTOP_USE_SAVED_HINT,
    PROFILE_SOURCE_DESKTOP_USE_SUBSCRIPTION_HINT,
    ROUTING_RULES_TITLE,
    SAVE_RULES,
    ROUTING_DESCRIPTION_DESKTOP,
    ROUTING_DESCRIPTION_VPN,
    ROUTING_DESCRIPTION_PROXY,
    APP_ASSIGNMENTS,
    APP_ASSIGNMENTS_DESCRIPTION_VPN,
    APP_ASSIGNMENTS_DESCRIPTION_PROXY,
    COUNTRY_CODE_DOMAINS,
    COUNTRY_CODE_DOMAINS_DESCRIPTION,
    BYPASS_DOMAINS,
    BYPASS_DOMAINS_DESCRIPTION,
    CURRENT_RULES,
    VPN_APPS_ASSIGNED,
    DOMAIN_RULE_COUNTS,
    IGNORE_RULES,
    IGNORE_RULES_ON_DOMAINS_ONLY,
    IGNORE_RULES_OFF_DOMAINS_ONLY,
    IGNORE_RULES_ON_APPS,
    IGNORE_RULES_OFF_APPS,
    IGNORE_RULES_ON_PROXY,
    IGNORE_RULES_OFF_PROXY,
    RESTART_VPN_AFTER_RULES,
    RESTART_PROXY_AFTER_RULES,
    SHOWN_COUNT,
    SEARCH_APPS_OR_PACKAGES,
    APP_ASSIGNMENTS_HELP,
    NO_APPS_MATCH,
    APPS_NOT_LOADED,
    SELECTED_COUNT,
    SELECT_ALL,
    CLEAR_ALL,
    PROXY_ONLY_RULES_DESCRIPTION,
    VPN_ON,
    VPN_OFF,
    SYSTEM_APP,
    REFRESHING,
    LOCAL_PROXY,
    LOCAL_PROXY_DESCRIPTION,
    PROXY_STATUS_RUNNING,
    PROXY_STATUS_STOPPED,
    COPY_ADDRESS,
    SHARE,
    SHARE_PROXY_ADDRESS,
    LOCATION_COUNT,
    MERGED_LOCATION_COUNT,
    NONE,
    DIFFERENT_SUBSCRIPTION,
    SUBSCRIPTION_LOCATION_LABEL,
    SAVED_LOCATION_LABEL,
    PROXY,
    SHOW_WINDOW,
    HIDE_WINDOW,
    EXIT,
}

class AppStrings(
    val language: AppLanguage,
) {
    fun get(key: UiText): String = generatedUiTextTranslations[language]?.get(key)
        ?: generatedUiTextTranslations[AppLanguage.ENGLISH]?.get(key)
        ?: key.name

    fun format(key: UiText, vararg args: Any?): String {
        var text = get(key)
        args.forEachIndexed { index, value ->
            text = text.replace("{$index}", value?.toString().orEmpty())
        }
        return text
    }

    fun languageDisplayName(language: AppLanguage, systemLanguageCode: String? = null): String {
        return if (language == AppLanguage.SYSTEM) {
            "${get(UiText.SETTINGS_LANGUAGE_SYSTEM)} (${language.effective(systemLanguageCode).nativeName})"
        } else {
            language.nativeName
        }
    }

    fun refreshPolicyTitle(policy: SubscriptionRefreshPolicy): String {
        return when (policy) {
            SubscriptionRefreshPolicy.OFF -> get(UiText.REFRESH_POLICY_OFF)
            SubscriptionRefreshPolicy.EVERY_HOUR -> get(UiText.REFRESH_POLICY_HOURLY)
            SubscriptionRefreshPolicy.CUSTOM -> get(UiText.REFRESH_POLICY_CUSTOM)
        }
    }

    fun refreshPolicyDisplay(policy: SubscriptionRefreshPolicy, customIntervalHours: Double): String {
        return when (policy) {
            SubscriptionRefreshPolicy.OFF,
            SubscriptionRefreshPolicy.EVERY_HOUR,
            -> refreshPolicyTitle(policy)
            SubscriptionRefreshPolicy.CUSTOM -> {
                "${refreshPolicyTitle(policy)} (${formatLocalizedRefreshInterval(subscriptionRefreshIntervalMinutes(customIntervalHours), language)})"
            }
        }
    }

    fun locationCountLabel(count: Int, merged: Boolean = false): String {
        return format(if (merged) UiText.MERGED_LOCATION_COUNT else UiText.LOCATION_COUNT, count)
    }

    fun locationLabel(prefixMode: com.kardinal.vpncontrol.model.ProfileSourceMode, name: String): String {
        val trimmed = name.trim()
        if (trimmed.isBlank()) return get(UiText.NONE)
        return when (prefixMode) {
            com.kardinal.vpncontrol.model.ProfileSourceMode.SUBSCRIPTION ->
                format(UiText.SUBSCRIPTION_LOCATION_LABEL, trimmed)
            com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS ->
                format(UiText.SAVED_LOCATION_LABEL, trimmed)
        }
    }

    fun validationSummary(settings: BenchmarkValidationSettings): String {
        val normalized = settings.normalized()
        return format(
            UiText.VALIDATION_SUMMARY,
            normalized.primaryUrl.displayHostForUi(),
            normalized.secondaryUrl.displayHostForUi(),
            normalized.batchSize,
            normalized.retryCount,
        )
    }

    fun statusTime(epochMillis: Long): String {
        if (epochMillis <= 0L) return get(UiText.NEVER)
        val local = Instant.fromEpochMilliseconds(epochMillis)
            .toLocalDateTime(TimeZone.currentSystemDefault())
        return buildString {
            append(local.year.toString().padStart(4, '0'))
            append('-')
            append(local.monthNumber.toString().padStart(2, '0'))
            append('-')
            append(local.dayOfMonth.toString().padStart(2, '0'))
            append(' ')
            append(local.hour.toString().padStart(2, '0'))
            append(':')
            append(local.minute.toString().padStart(2, '0'))
        }
    }

    fun statusMessage(message: String): String {
        val trimmed = message.trim()
        if (trimmed.isBlank()) return trimmed
        StatusMessages.decode(trimmed)?.let { return localizedStructuredStatusMessage(language, it) }
        localizedBenchmarkMessage(language, trimmed)?.let { return it }
        localizedDynamicStatusMessage(language, trimmed)?.let { return it }
        localizedGeneratedStatusMessage(language, trimmed)?.let { return it }
        return trimmed
    }
}

private fun localizedStructuredStatusMessage(
    language: AppLanguage,
    status: StructuredStatusMessage,
): String {
    val resolvedLanguage = if (language == AppLanguage.SYSTEM) AppLanguage.ENGLISH else language
    val keys = structuredStatusTemplateKeys(status)
    val template = keys.firstNotNullOfOrNull { key ->
        generatedStatusTranslations[resolvedLanguage]?.structured?.get(key)
    } ?: keys.firstNotNullOfOrNull { key ->
        generatedStatusTranslations[AppLanguage.ENGLISH]?.structured?.get(key)
    } ?: status.key.name
    return renderStructuredStatusTemplate(resolvedLanguage, status, template)
}

internal fun structuredStatusTemplateKeys(status: StructuredStatusMessage): List<String> {
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    fun mode(index: Int): String = if (arg(index).isProxyMode()) "PROXY_ONLY" else "VPN"
    fun profileSource(index: Int): String =
        if (arg(index).equals("CURRENT_LOCATIONS", ignoreCase = true)) "CURRENT_LOCATIONS" else "SUBSCRIPTION"
    fun bool(index: Int): String = if (arg(index).equals("true", ignoreCase = true)) "TRUE" else "FALSE"
    fun modeVariantKey() = "${status.key.name}.${mode(0)}"

    val specific = when (status.key) {
        StatusMessageKey.LANGUAGE_SET ->
            if (arg(0).isBlank()) "${status.key.name}.SYSTEM" else null
        StatusMessageKey.STARTING_CONNECTION,
        StatusMessageKey.STARTING_CONNECTION_WITH_BEST,
        StatusMessageKey.CONNECTION_STARTED,
        StatusMessageKey.CONNECTION_STOPPED,
        StatusMessageKey.CONNECTION_READY_ON_COMPUTER,
        StatusMessageKey.RUNTIME_MODE,
        StatusMessageKey.PREFLIGHT_PASSED,
        StatusMessageKey.PREFLIGHT_FAILED,
        StatusMessageKey.SELECTED_LOCATION_REMOVED_CONNECTION_STOPPED,
        StatusMessageKey.LOCATION_REMOVAL_ROLLBACK_FAILED,
        StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE_CONNECTION_STOPPED,
        StatusMessageKey.LOCATIONS_IMPORT_ROLLBACK_FAILED,
        StatusMessageKey.ROUTING_RULES_IMPORTED_RESTART_REQUIRED,
        StatusMessageKey.APP_MODE_CHANGED,
        StatusMessageKey.CONNECTION_STARTED_ON_TARGET,
        StatusMessageKey.CONNECTION_START_FAILED,
        StatusMessageKey.CONNECTION_STOP_FAILED,
        StatusMessageKey.SELECTED_LOCATION_STARTED_SAVE_FAILED,
        StatusMessageKey.BEST_LOCATION_START_FAILED,
        StatusMessageKey.BEST_LOCATION_STARTED_SAVE_FAILED,
        StatusMessageKey.CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH,
        StatusMessageKey.CONNECTION_STOP_BEFORE_EXIT_FAILED -> modeVariantKey()
        StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR ->
            if (arg(0).isBlank()) "${status.key.name}.EMPTY" else null
        StatusMessageKey.PROFILE_SOURCE_MODE,
        StatusMessageKey.PROFILE_SOURCE_SET -> "${status.key.name}.${profileSource(0)}"
        StatusMessageKey.UI_SETTING_VISIBILITY_CHANGED -> "${status.key.name}.${arg(0)}.${bool(1)}"
        StatusMessageKey.CONNECTION_MODE_SET -> "${status.key.name}.${mode(0)}"
        StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED,
        StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED ->
            if (arg(0).isBlank()) null else "${status.key.name}.DETAIL"
        StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE -> "${status.key.name}.${mode(0)}.${mode(1)}"
        else -> null
    }
    return listOfNotNull(specific, status.key.name)
}

private val structuredPlaceholderRegex = Regex("\\{([^{}]+)}")

private fun renderStructuredStatusTemplate(
    language: AppLanguage,
    status: StructuredStatusMessage,
    template: String,
): String = structuredPlaceholderRegex.replace(template) { match ->
    val token = match.groupValues[1]
    renderStructuredPlaceholder(language, status, token) ?: match.value
}

private fun renderStructuredPlaceholder(
    language: AppLanguage,
    status: StructuredStatusMessage,
    token: String,
): String? {
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    return token.toIntOrNull()?.let { arg(it) } ?: when (token) {
        "refreshInterval" -> structuredRefreshInterval(language, status)
        "checkCount" -> structuredCheckCount(language, arg(1).toIntOrNull() ?: 0)
        "valueOrNotReady" -> arg(0).ifBlank {
            localizedGeneratedStatusMessage(language, "not ready") ?: "not ready"
        }
        else -> null
    } ?: renderStructuredNamedPlaceholder(language, status, token)
}

private fun renderStructuredNamedPlaceholder(
    language: AppLanguage,
    status: StructuredStatusMessage,
    token: String,
): String? {
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    fun ui(key: UiText): String =
        generatedUiTextTranslations[language]?.get(key)
            ?: generatedUiTextTranslations[AppLanguage.ENGLISH]?.get(key)
            ?: key.name
    fun modeLabel(mode: String): String = if (mode.isProxyMode()) ui(UiText.PROXY_ONLY) else ui(UiText.VPN)
    fun connectionLabel(mode: String): String = if (mode.isProxyMode()) ui(UiText.PROXY) else ui(UiText.VPN)

    val parts = token.split(':')
    return when (parts.firstOrNull()) {
        "ui" -> parts.getOrNull(1)
            ?.let { runCatching { UiText.valueOf(it) }.getOrNull() }
            ?.let(::ui)
        "modeLabel" -> parts.getOrNull(1)?.toIntOrNull()?.let { modeLabel(arg(it)) }
        "connectionLabel" -> parts.getOrNull(1)?.toIntOrNull()?.let { connectionLabel(arg(it)) }
        else -> null
    }
}

private fun structuredRefreshInterval(
    language: AppLanguage,
    status: StructuredStatusMessage,
): String {
    val policyName = status.args.getOrNull(0).orEmpty()
    val intervalMinutes = status.args.getOrNull(1)?.toIntOrNull()
    return when (policyName) {
        SubscriptionRefreshPolicy.OFF.name ->
            generatedUiTextTranslations[language]?.get(UiText.REFRESH_POLICY_OFF)
                ?: generatedUiTextTranslations[AppLanguage.ENGLISH]?.get(UiText.REFRESH_POLICY_OFF)
                ?: "Off"
        SubscriptionRefreshPolicy.EVERY_HOUR.name ->
            formatLocalizedRefreshInterval(60, language, includeEvery = true)
        else ->
            formatLocalizedRefreshInterval(intervalMinutes ?: 0, language, includeEvery = true)
    }
}

private fun structuredCheckCount(language: AppLanguage, count: Int): String {
    val english = "$count check${if (count == 1) "" else "s"}"
    return localizedGeneratedStatusMessage(language, english) ?: english
}

private fun String.isProxyMode(): Boolean =
    equals("PROXY_ONLY", ignoreCase = true) ||
        equals("Proxy", ignoreCase = true) ||
        equals("proxy", ignoreCase = true)

private fun matchStatusTemplate(
    template: String,
    text: String,
    placeholderPatterns: Map<String, String>,
): Map<String, String>? {
    val names = mutableListOf<String>()
    var cursor = 0
    val pattern = buildString {
        append('^')
        structuredPlaceholderRegex.findAll(template).forEach { match ->
            append(Regex.escape(template.substring(cursor, match.range.first)))
            val name = match.groupValues[1]
            names += name
            append('(')
            append(placeholderPatterns[name] ?: ".+?")
            append(')')
            cursor = match.range.last + 1
        }
        append(Regex.escape(template.substring(cursor)))
        append('$')
    }
    val result = Regex(pattern).matchEntire(text) ?: return null
    return names.mapIndexed { index, name -> name to result.groupValues[index + 1] }.toMap()
}

private fun localizedDynamicStatusMessage(language: AppLanguage, text: String): String? {
    val words = generatedStatusTranslations[language]?.dynamic ?: return null
    val sourceWords = generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic ?: return null
    matchStatusTemplate(
        template = sourceWords.checkingLocations,
        text = text,
        placeholderPatterns = mapOf("count" to "\\d+"),
    )?.let {
        return words.checkingLocations.replace("{count}", it.getValue("count"))
    }
    matchStatusTemplate(
        template = sourceWords.testingLocationsRange,
        text = text,
        placeholderPatterns = mapOf(
            "start" to "\\d+",
            "end" to "\\d+",
            "total" to "\\d+",
        ),
    )?.let {
        return words.testingLocationsRange
            .replace("{start}", it.getValue("start"))
            .replace("{end}", it.getValue("end"))
            .replace("{total}", it.getValue("total"))
    }

    val testingSuffix = " ${sourceWords.testingFastestCandidates}"
    if (!text.endsWith(testingSuffix)) return null
    val translatedPrefix = when (text.removeSuffix(testingSuffix)) {
        sourceWords.findingSubscription -> words.findingSubscription
        sourceWords.findingSaved -> words.findingSaved
        else -> return null
    }
    return "$translatedPrefix ${words.testingFastestCandidates}"
}

private fun localizedBenchmarkMessage(language: AppLanguage, text: String): String? {
    val words = generatedStatusTranslations[language]?.benchmark ?: return null
    val sourceWords = generatedStatusTranslations[AppLanguage.ENGLISH]?.benchmark ?: return null
    val segments = text.split(" • ")
    var changed = false
    val translated = segments.joinToString(" • ") { segment ->
        when {
            segment.startsWith(sourceWords.best) -> {
                changed = true
                words.best + segment.removePrefix(sourceWords.best)
            }
            segment.startsWith(sourceWords.primary) -> {
                changed = true
                words.primary + translateBenchmarkStatus(segment.removePrefix(sourceWords.primary), words, sourceWords)
            }
            segment.startsWith(sourceWords.secondary) -> {
                changed = true
                words.secondary + translateBenchmarkStatus(segment.removePrefix(sourceWords.secondary), words, sourceWords)
            }
            segment.startsWith(sourceWords.tcp) -> {
                changed = true
                words.tcp + translateBenchmarkStatus(segment.removePrefix(sourceWords.tcp), words, sourceWords)
            }
            else -> segment
        }
    }
    return translated.takeIf { changed && it != text }
}

private fun translateBenchmarkStatus(
    status: String,
    words: GeneratedBenchmarkWords,
    sourceWords: GeneratedBenchmarkWords,
): String {
    Regex("^([0-9]+(?:\\.[0-9]+)?)\\s*${Regex.escape(sourceWords.millisUnit)}$").matchEntire(status)?.let {
        return "${it.groupValues[1]} ${words.millisUnit}"
    }
    val sourceStatus = sourceWords.statuses.entries.firstOrNull { it.value == status }?.key ?: status
    return words.statuses[sourceStatus] ?: status
}

private fun formatLocalizedRefreshInterval(
    minutes: Int,
    language: AppLanguage,
    includeEvery: Boolean = false,
): String {
    val normalizedMinutes = minutes.coerceAtLeast(1)
    val hours = normalizedMinutes / 60
    val remainingMinutes = normalizedMinutes % 60
    val words = generatedStatusTranslations[language]?.dynamic
        ?: generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic
    fun template(value: String?, fallback: String): String = value ?: fallback
    fun baseLabel(): String = when {
        normalizedMinutes < 60 -> template(words?.refreshIntervalMinutes, "{count} min")
            .replace("{count}", normalizedMinutes.toString())
        remainingMinutes == 0 -> template(words?.refreshIntervalHours, "{count} h")
            .replace("{count}", hours.toString())
        else -> template(words?.refreshIntervalHoursMinutes, "{hours} h {minutes} min")
            .replace("{hours}", hours.toString())
            .replace("{minutes}", remainingMinutes.toString())
    }
    val label = baseLabel()
    return if (!includeEvery) {
        label
    } else if (normalizedMinutes == 60) {
        template(words?.refreshIntervalEveryHour, "every hour")
    } else {
        template(words?.refreshIntervalEvery, "every {interval}")
            .replace("{interval}", label)
    }
}

private fun String.displayHostForUi(): String {
    val withoutScheme = substringAfter("://", this)
    val authority = withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
    val hostPort = authority.substringAfterLast('@')
    val host = if (hostPort.startsWith("[")) {
        hostPort.substringAfter('[').substringBefore(']')
    } else {
        hostPort.substringBefore(':')
    }
    return host.removePrefix("www.").ifBlank { this }
}

internal fun String.replaceEnglishRefreshIntervals(language: AppLanguage): String {
    return Regex("\\bevery (\\d+) h (\\d+) min\\b").replace(this) { match ->
        val minutes = match.groupValues[1].toInt() * 60 + match.groupValues[2].toInt()
        formatLocalizedRefreshInterval(minutes, language, includeEvery = true)
    }.let { text ->
        Regex("\\bevery (\\d+) min\\b").replace(text) { match ->
            formatLocalizedRefreshInterval(match.groupValues[1].toInt(), language, includeEvery = true)
        }
    }.let { text ->
        Regex("\\bevery (\\d+) h\\b").replace(text) { match ->
            formatLocalizedRefreshInterval(match.groupValues[1].toInt() * 60, language, includeEvery = true)
        }
    }.let { text ->
        Regex("\\bevery (\\d+) minutes?\\b").replace(text) { match ->
            formatLocalizedRefreshInterval(match.groupValues[1].toInt(), language, includeEvery = true)
        }
    }.let { text ->
        Regex("\\bevery (\\d+) hours?\\b").replace(text) { match ->
            formatLocalizedRefreshInterval(match.groupValues[1].toInt() * 60, language, includeEvery = true)
        }
    }.let { text ->
        text.replace("every hour", formatLocalizedRefreshInterval(60, language, includeEvery = true))
    }
}

val LocalAppStrings = compositionLocalOf { AppStrings(AppLanguage.ENGLISH) }

@Composable
fun rememberAppStrings(
    languageOverride: AppLanguage,
    systemLanguageCode: String?,
): AppStrings {
    val effective = languageOverride.effective(systemLanguageCode)
    return remember(effective) { AppStrings(effective) }
}

internal fun missingUiTextLocalizationKeys(): Map<AppLanguage, List<UiText>> = missingGeneratedUiTextLocalizationKeys()

internal fun missingGeneratedUiTextLocalizationKeys(): Map<AppLanguage, List<UiText>> {
    return AppLanguage.entries
        .filter { it != AppLanguage.SYSTEM }
        .associateWith { language ->
            UiText.entries.filter { key ->
                generatedUiTextTranslations[language]?.containsKey(key) != true
            }
        }
        .filterValues { it.isNotEmpty() }
}
