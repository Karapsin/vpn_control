package com.kardinal.vpncontrol.shared.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.StatusMessages
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
    DNS_MODE_AUTOMATIC,
    DNS_MODE_DOH,
    DNS_MODE_DOT,
    DNS_SECURE_ENDPOINT,
    DNS_LEGACY_MIGRATION_NOTICE,
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
    TEST_SITE,
    BATCH_SIZE,
    RETRY_COUNT,
    ACTIVE_VERIFICATION_WINDOW,
    TEST_SITE_PLACEHOLDER,
    VALIDATION_ANDROID_SUMMARY,
    VALIDATION_DESKTOP_SUMMARY,
    VALIDATION_SUMMARY,
    SUBSCRIPTION_REFRESH_CONCURRENCY,
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
    ROUTING_DESCRIPTION_DESKTOP,
    ROUTING_DESCRIPTION_VPN,
    ROUTING_DESCRIPTION_PROXY,
    APP_ASSIGNMENTS,
    APP_ASSIGNMENTS_DESCRIPTION_VPN,
    APP_ASSIGNMENTS_DESCRIPTION_PROXY,
    BYPASS_DOMAINS,
    BYPASS_DOMAINS_DESCRIPTION,
    QUIC_COMPATIBILITY,
    QUIC_COMPATIBILITY_DESCRIPTION,
    BLOCK_QUIC_UDP_443,
    BLOCK_QUIC_UDP_443_HELP,
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
            normalized.testUrl.displayHostForUi(),
            normalized.batchSize,
            normalized.subscriptionRefreshConcurrency,
            normalized.retryCount,
            normalized.activeVerificationWindowSize,
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
