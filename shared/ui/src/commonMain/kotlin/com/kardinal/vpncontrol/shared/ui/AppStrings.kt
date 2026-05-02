package com.kardinal.vpncontrol.shared.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.StructuredStatusMessage
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
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
    val english = englishStructuredStatusMessage(status)
    if (language == AppLanguage.ENGLISH || language == AppLanguage.SYSTEM) return english
    localizedDesktopSettingsStatusMessage(language, status)?.let { return it }
    localizedLocationStatusMessage(language, status)?.let { return it }
    return localizedGeneratedStatusMessage(language, english) ?: english
}

private fun localizedDesktopSettingsStatusMessage(
    language: AppLanguage,
    status: StructuredStatusMessage,
): String? {
    fun ui(key: UiText): String =
        generatedUiTextTranslations[language]?.get(key)
            ?: generatedUiTextTranslations[AppLanguage.ENGLISH]?.get(key)
            ?: key.name

    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    fun modeLabel(mode: String): String = if (mode.isProxyMode()) ui(UiText.PROXY_ONLY) else ui(UiText.VPN)
    fun connectionLabel(mode: String): String = if (mode.isProxyMode()) ui(UiText.PROXY) else ui(UiText.VPN)
    fun withDetail(base: String, detail: String): String =
        if (detail.isBlank()) base else "$base: $detail"

    return when (status.key) {
        StatusMessageKey.START_ON_LOGIN_ENABLED ->
            "${ui(UiText.SETTINGS_START_ON_LOGIN)}: ${ui(UiText.SETTINGS_ENABLED)}"
        StatusMessageKey.START_ON_LOGIN_DISABLED ->
            "${ui(UiText.SETTINGS_START_ON_LOGIN)}: ${ui(UiText.SETTINGS_DISABLED)}"
        StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED ->
            withDetail(
                localizedGeneratedStatusMessage(language, "Failed to update startup setting")
                    ?: "Failed to update startup setting",
                arg(0),
            )
        StatusMessageKey.SUBSCRIPTION_HWID_CLEARED ->
            "x-hwid: ${ui(UiText.SETTINGS_DISABLED)}"
        StatusMessageKey.SUBSCRIPTION_HWID_SAVED ->
            "x-hwid: ${ui(UiText.SETTINGS_ENABLED)}"
        StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED ->
            withDetail(
                localizedGeneratedStatusMessage(language, "Failed to save refresh settings")
                    ?: "Failed to save refresh settings",
                arg(0),
            )
        StatusMessageKey.APP_MODE_CHANGED ->
            "${ui(UiText.SETTINGS_VPN_PROXY_MODE)}: ${modeLabel(arg(0))}"
        StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE ->
            "${connectionLabel(arg(0))} ${ui(UiText.STOPPED)}. ${ui(UiText.SETTINGS_VPN_PROXY_MODE)}: ${modeLabel(arg(1))}"
        else -> null
    }
}

private fun localizedLocationStatusMessage(
    language: AppLanguage,
    status: StructuredStatusMessage,
): String? {
    val words = generatedStatusTranslations[language]?.dynamic ?: return null
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    return when (status.key) {
        StatusMessageKey.SELECT_LOCATION_FIRST -> words.selectLocationFirst
        StatusMessageKey.CHECKING_LOCATION -> words.checkingLocation.replace("{name}", arg(0))
        StatusMessageKey.TESTING_LOCATION -> words.testingLocation.replace("{name}", arg(0))
        StatusMessageKey.LOCATION_CHECK_CANCELLED -> words.locationCheckCancelled
        StatusMessageKey.NO_LOCATIONS_TO_EXPORT -> words.noLocationsToExport
        else -> null
    }
}

private fun englishStructuredStatusMessage(status: StructuredStatusMessage): String {
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    return when (status.key) {
        StatusMessageKey.IDLE -> "Idle"
        StatusMessageKey.LANGUAGE_SET -> "Language set to ${arg(0).ifBlank { "system default" }}"
        StatusMessageKey.SUBSCRIPTION_AUTO_REFRESH_SET ->
            englishRefreshStatus(arg(0), arg(1).toIntOrNull())
        StatusMessageKey.VALIDATION_SETTINGS_SAVED ->
            "Validation settings saved: ${arg(0)} • ${arg(1)} • batch ${arg(2)} • retries ${arg(3)}"
        StatusMessageKey.CUSTOM_DNS_SAVED -> "Custom DNS saved"
        StatusMessageKey.CUSTOM_DNS_DISABLED -> "Custom DNS disabled"
        StatusMessageKey.FIND_BEST_FROM_SUBSCRIPTION ->
            generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.findingSubscription
                ?: "Finding the best location from the subscription..."
        StatusMessageKey.FIND_BEST_FROM_SAVED ->
            generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.findingSaved
                ?: "Finding the best location from saved locations..."
        StatusMessageKey.STARTING_CONNECTION ->
            englishStartingConnection(arg(0), withBestLocation = false)
        StatusMessageKey.STARTING_CONNECTION_WITH_BEST ->
            englishStartingConnection(arg(0), withBestLocation = true)
        StatusMessageKey.CONNECTION_STARTED ->
            if (arg(0).isProxyMode()) "Proxy started" else "VPN started"
        StatusMessageKey.CONNECTION_STOPPED ->
            if (arg(0).isProxyMode()) "Proxy stopped" else "VPN stopped"
        StatusMessageKey.CONNECTION_READY_ON_COMPUTER ->
            if (arg(0).isProxyMode()) "Proxy ready on this computer" else "VPN ready on this computer"
        StatusMessageKey.DESKTOP_APP_INITIALIZED -> "App initialized"
        StatusMessageKey.RUNTIME_MODE -> "Runtime mode: ${englishConnectionDisplay(arg(0))}"
        StatusMessageKey.LOCAL_PROXY -> "Local proxy: ${arg(0)}"
        StatusMessageKey.RUNTIME_LOG -> "Runtime log: ${arg(0)}"
        StatusMessageKey.PREFLIGHT_PASSED -> "${englishConnectionDisplay(arg(0))} mode preflight passed"
        StatusMessageKey.PREFLIGHT_FAILED -> {
            val failedChecks = arg(1).toIntOrNull() ?: 0
            val checks = "$failedChecks check${if (failedChecks == 1) "" else "s"}"
            "${englishConnectionDisplay(arg(0))} mode preflight failed: $checks"
        }
        StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY -> "Desktop VPN capability: ready"
        StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR ->
            "Desktop VPN capability: ${arg(0).ifBlank { "not ready" }}"
        StatusMessageKey.NO_LOCATIONS_AVAILABLE_FOR_BENCHMARKING -> "No locations available for benchmarking"
        StatusMessageKey.BEST_LOCATION_SEARCH_TIMED_OUT -> "Best location search timed out; keeping the current connection"
        StatusMessageKey.NO_SUITABLE_LOCATION_FOUND -> "No suitable location found"
        StatusMessageKey.BEST_LOCATION_NOT_MAPPED -> "Best location could not be mapped to the desktop list"
        StatusMessageKey.ACTIVATED_ALL_SUBSCRIPTIONS -> "Activated all subscriptions"
        StatusMessageKey.ACTIVATED_SUBSCRIPTION -> "Activated ${arg(0)}"
        StatusMessageKey.PROFILE_SOURCE_MODE -> "Profile source mode: ${arg(0)}"
        StatusMessageKey.SUBSCRIPTION_NAME_RESET -> "Subscription name reset"
        StatusMessageKey.SUBSCRIPTION_NAME_SAVED -> "Subscription name saved"
        StatusMessageKey.SUBSCRIPTION_DELETED -> "Subscription deleted"
        StatusMessageKey.SELECT_LOCATION_FIRST ->
            generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.selectLocationFirst
                ?: "Select a location first"
        StatusMessageKey.CHECKING_LOCATION ->
            (generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.checkingLocation
                ?: "Checking {name}...").replace("{name}", arg(0))
        StatusMessageKey.TESTING_LOCATION ->
            (generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.testingLocation
                ?: "Testing {name}...").replace("{name}", arg(0))
        StatusMessageKey.LOCATION_CHECK_CANCELLED ->
            generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.locationCheckCancelled
                ?: "Location check cancelled"
        StatusMessageKey.NO_LOCATIONS_TO_EXPORT ->
            generatedStatusTranslations[AppLanguage.ENGLISH]?.dynamic?.noLocationsToExport
                ?: "No locations to export"
        StatusMessageKey.UI_SETTING_VISIBILITY_CHANGED ->
            englishUiSettingVisibility(arg(0), arg(1).equals("true", ignoreCase = true))
        StatusMessageKey.SUBSCRIPTION_LOCATION_SAVE_READ_ONLY ->
            "Subscription locations are read-only. Switch to Saved Locations to save edits."
        StatusMessageKey.INVALID_LOCATION_CONFIG -> "Invalid location config"
        StatusMessageKey.LOCATION_ALREADY_SAVED -> "Location already saved: ${arg(0)}"
        StatusMessageKey.LOCATION_EDIT_UNAVAILABLE -> "Location to edit is no longer available"
        StatusMessageKey.LOCATION_ADDED -> "Location added: ${arg(0)}"
        StatusMessageKey.LOCATION_UPDATED_AND_MERGED -> "Location updated and merged: ${arg(0)}"
        StatusMessageKey.LOCATION_UPDATED -> "Location updated: ${arg(0)}"
        StatusMessageKey.SUBSCRIPTION_LOCATION_DELETE_READ_ONLY ->
            "Subscription locations are read-only. Switch to Saved Locations to delete them."
        StatusMessageKey.SELECTED_LOCATION_REMOVED -> "Selected location removed: ${arg(0)}"
        StatusMessageKey.LOCATION_REMOVED -> "Location removed: ${arg(0)}"
        StatusMessageKey.SELECTED_LOCATION_REMOVED_CONNECTION_STOPPED ->
            "Selected location removed. ${englishConnectionDisplay(arg(0))} stopped: ${arg(1)}"
        StatusMessageKey.LOCATION_REMOVAL_ROLLBACK_FAILED ->
            "Location removal rolled back because the ${englishConnectionNoun(arg(0))} could not be stopped"
        StatusMessageKey.IMPORT_LOCATIONS_BLOCKED -> "Switch to Saved Locations to import locations"
        StatusMessageKey.IMPORT_LOCATIONS_FAILED -> "Failed to import locations"
        StatusMessageKey.LOCATIONS_IMPORTED -> "Locations imported"
        StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE ->
            "Locations imported. Selected location is no longer available"
        StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE_CONNECTION_STOPPED ->
            "Locations imported. Selected location is no longer available, ${englishConnectionNounLower(arg(0))} stopped"
        StatusMessageKey.LOCATIONS_IMPORT_ROLLBACK_FAILED ->
            "Locations import rolled back because the ${englishConnectionNoun(arg(0))} could not be stopped"
        StatusMessageKey.CLIPBOARD_EMPTY -> "Clipboard is empty"
        StatusMessageKey.CLIPBOARD_READ_FAILED -> "Clipboard read failed"
        StatusMessageKey.SUBSCRIPTION_TEXT_LOADED_INTO_PROFILE -> "Subscription text loaded into the Profile tab"
        StatusMessageKey.PROFILE_SOURCE_SET ->
            if (arg(0) == ProfileSourceMode.SUBSCRIPTION.name) {
                "Profile source set to subscription"
            } else {
                "Profile source set to saved locations"
            }
        StatusMessageKey.DISCONNECT_FIRST_CHANGE_CONNECTION_MODE -> "Disconnect first to change connection mode"
        StatusMessageKey.CONNECTION_MODE_SET ->
            if (arg(0).isProxyMode()) "Connection mode set to proxy only" else "Connection mode set to VPN"
        StatusMessageKey.RULE_SET_REMOVED -> "Rule-set removed"
        StatusMessageKey.SWITCH_TO_SAVED_LOCATIONS_TO_ADD_LOCATIONS ->
            "Switch to Saved Locations to add locations manually"
        StatusMessageKey.HISTORY_ENTRY_DELETED -> "History entry deleted"
        StatusMessageKey.SELECTED_LOCATION_UNCHANGED -> "Selected location unchanged: ${arg(0)}"
        StatusMessageKey.SELECTED_LOCATION_SET -> "Selected location set: ${arg(0)}"
        StatusMessageKey.LOCATION_CHECKED -> "Location checked: ${arg(0)}"
        StatusMessageKey.LOCATION_CHECK_FAILED -> "Location check failed"
        StatusMessageKey.LOCATION_EDITED -> "Edited location #${arg(0)}"
        StatusMessageKey.SAMPLE_RULE_SET_ADDED -> "Added a sample rule-set"
        StatusMessageKey.RULE_SET_DELETED -> "Deleted rule-set ${arg(0)}"
        StatusMessageKey.ROUTING_RULES_SAVED -> "Routing rules saved"
        StatusMessageKey.ROUTING_RULES_IMPORTED -> "Routing rules imported"
        StatusMessageKey.ROUTING_RULES_IMPORTED_RESTART_REQUIRED ->
            "Routing rules imported. Restart ${englishConnectionNoun(arg(0))} to apply"
        StatusMessageKey.ROUTING_RULES_IMPORT_FAILED -> "Failed to import routing rules"
        StatusMessageKey.ROUTING_RULES_COPIED_TO_CLIPBOARD -> "Routing rules copied to clipboard"
        StatusMessageKey.ROUTING_RULES_EXPORT_CANCELED -> "Routing rules export canceled"
        StatusMessageKey.ROUTING_RULES_EXPORTED_TO -> "Routing rules exported to ${arg(0)}"
        StatusMessageKey.ROUTING_RULES_EXPORT_FAILED -> "Failed to export routing rules"
        StatusMessageKey.ROUTING_RULES_FILE_OPEN_FAILED -> "Failed to open routing rules file"
        StatusMessageKey.LOCATIONS_COPIED_TO_CLIPBOARD -> "Locations copied to clipboard"
        StatusMessageKey.LOCATIONS_EXPORT_CANCELED -> "Locations export canceled"
        StatusMessageKey.LOCATIONS_EXPORTED_TO -> "Locations exported to ${arg(0)}"
        StatusMessageKey.LOCATIONS_EXPORT_FAILED -> "Failed to export locations"
        StatusMessageKey.LOCATIONS_FILE_OPEN_FAILED -> "Failed to open locations file"
        StatusMessageKey.LOCATIONS_FILE_READ_FAILED -> "Failed to read locations file"
        StatusMessageKey.DIAGNOSTICS_EXPORT_CANCELED -> "Diagnostics export canceled"
        StatusMessageKey.DIAGNOSTICS_EXPORTED_TO -> "Diagnostics exported to ${arg(0)}"
        StatusMessageKey.DIAGNOSTICS_EXPORT_FAILED -> "Failed to export diagnostics"
        StatusMessageKey.DIAGNOSTICS_DESTINATION_OPEN_FAILED -> "Failed to open diagnostics destination"
        StatusMessageKey.NO_SUBSCRIPTIONS_TO_REFRESH -> "No subscriptions to refresh"
        StatusMessageKey.START_ON_LOGIN_ENABLED -> "App will start automatically after login"
        StatusMessageKey.START_ON_LOGIN_DISABLED -> "App startup on login disabled"
        StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED ->
            appendStatusDetail("Failed to update startup setting", arg(0))
        StatusMessageKey.SUBSCRIPTION_HWID_CLEARED ->
            "Subscription x-hwid cleared. A new ID will be generated on the next refresh."
        StatusMessageKey.SUBSCRIPTION_HWID_SAVED ->
            "Subscription x-hwid saved. Refresh the subscription to use it."
        StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED ->
            appendStatusDetail("Failed to save refresh settings", arg(0))
        StatusMessageKey.APP_MODE_CHANGED ->
            "App mode: ${englishConnectionDisplay(arg(0))}"
        StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE ->
            "${englishConnectionDisplay(arg(0))} stopped. App mode: ${englishConnectionDisplay(arg(1))}"
        StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_PENDING -> "Previous VPN session will be restored"
        StatusMessageKey.PREVIOUS_LOCATION_UNAVAILABLE -> "Previous VPN location is no longer available"
        StatusMessageKey.RESTORING_PREVIOUS_CONNECTION -> "Restoring VPN: ${arg(0)}..."
        StatusMessageKey.CONNECTION_STARTED_ON_TARGET ->
            "${englishConnectionDisplay(arg(0))} started on ${arg(1)}"
        StatusMessageKey.CONNECTION_START_FAILED ->
            "Failed to start ${englishConnectionNoun(arg(0))}"
        StatusMessageKey.CONNECTION_STOP_FAILED ->
            "Failed to stop ${englishConnectionNoun(arg(0))}"
        StatusMessageKey.APP_CLOSED_CONNECTION_WAS_OFF -> "App closed. VPN was off."
        StatusMessageKey.CONNECTION_STOPPED_RECONNECT_ON_NEXT_LAUNCH ->
            "${englishConnectionDisplay(arg(0))} stopped. Will reconnect on next launch."
        StatusMessageKey.CONNECTION_STOP_BEFORE_EXIT_FAILED ->
            "Failed to stop ${englishConnectionDisplay(arg(0))} before exit"
    }
}

private fun appendStatusDetail(base: String, detail: String): String =
    if (detail.isBlank()) base else "$base: $detail"

private fun englishRefreshStatus(
    policyName: String,
    intervalMinutes: Int?,
): String {
    val value = when {
        policyName == SubscriptionRefreshPolicy.OFF.name -> "off"
        intervalMinutes != null -> formatLocalizedRefreshInterval(intervalMinutes, AppLanguage.ENGLISH, includeEvery = true)
        policyName == SubscriptionRefreshPolicy.EVERY_HOUR.name ->
            formatLocalizedRefreshInterval(60, AppLanguage.ENGLISH, includeEvery = true)
        else -> "custom interval"
    }
    return "Subscription auto-refresh set to $value"
}

private fun englishStartingConnection(
    mode: String,
    withBestLocation: Boolean,
): String {
    val isProxy = mode.isProxyMode()
    return when {
        withBestLocation && isProxy -> "Starting local proxy with the best location..."
        withBestLocation -> "Starting VPN with the best location..."
        isProxy -> "Starting local proxy..."
        else -> "Starting VPN..."
    }
}

private fun englishConnectionDisplay(mode: String): String =
    if (mode.isProxyMode()) "Proxy" else "VPN"

private fun englishConnectionNoun(mode: String): String =
    if (mode.isProxyMode()) "proxy" else "VPN"

private fun englishConnectionNounLower(mode: String): String =
    if (mode.isProxyMode()) "proxy" else "vpn"

private fun englishUiSettingVisibility(
    itemName: String,
    enabled: Boolean,
): String {
    val item = UiSettingsStatusItem.entries.firstOrNull { it.name == itemName }
    return when (item) {
        UiSettingsStatusItem.SESSION_STATS ->
            if (enabled) "Session stats enabled" else "Session stats hidden"
        UiSettingsStatusItem.LIVE_TRAFFIC_STATS ->
            if (enabled) "Live traffic stats enabled" else "Live traffic stats hidden"
        UiSettingsStatusItem.PROFILE_TOTALS ->
            if (enabled) "Per-profile totals enabled" else "Per-profile totals hidden"
        UiSettingsStatusItem.LATENCY_HISTORY ->
            if (enabled) "Latency history enabled" else "Latency history hidden"
        UiSettingsStatusItem.CONNECTION_LOG ->
            if (enabled) "Connection log enabled" else "Connection log hidden"
        UiSettingsStatusItem.CONNECTION_TEST_TOOLS ->
            if (enabled) "Connection test tools enabled" else "Connection test tools hidden"
        null -> if (enabled) "Settings enabled" else "Settings hidden"
    }
}

private fun String.isProxyMode(): Boolean =
    equals("PROXY_ONLY", ignoreCase = true) ||
        equals("Proxy", ignoreCase = true) ||
        equals("proxy", ignoreCase = true)

private fun localizedDynamicStatusMessage(language: AppLanguage, text: String): String? {
    val words = generatedStatusTranslations[language]?.dynamic ?: return null
    Regex("^Checking (\\d+) locations\\.\\.\\.$").matchEntire(text)?.let {
        return words.checkingLocations.replace("{count}", it.groupValues[1])
    }
    Regex("^Testing locations (\\d+)-(\\d+) of (\\d+)\\.\\.\\.$").matchEntire(text)?.let {
        return words.testingLocationsRange
            .replace("{start}", it.groupValues[1])
            .replace("{end}", it.groupValues[2])
            .replace("{total}", it.groupValues[3])
    }

    val testingSuffix = " Testing fastest candidates in batches..."
    if (!text.endsWith(testingSuffix)) return null
    val translatedPrefix = when (text.removeSuffix(testingSuffix)) {
        "Finding the best location from the subscription..." -> words.findingSubscription
        "Finding the best location from saved locations..." -> words.findingSaved
        else -> return null
    }
    return "$translatedPrefix ${words.testingFastestCandidates}"
}

private fun localizedBenchmarkMessage(language: AppLanguage, text: String): String? {
    val words = generatedStatusTranslations[language]?.benchmark ?: return null
    val segments = text.split(" • ")
    var changed = false
    val translated = segments.joinToString(" • ") { segment ->
        when {
            segment.startsWith("Best: ") -> {
                changed = true
                words.best + segment.removePrefix("Best: ")
            }
            segment.startsWith("primary ") -> {
                changed = true
                words.primary + translateBenchmarkStatus(segment.removePrefix("primary "), words)
            }
            segment.startsWith("secondary ") -> {
                changed = true
                words.secondary + translateBenchmarkStatus(segment.removePrefix("secondary "), words)
            }
            segment.startsWith("tcp ") -> {
                changed = true
                words.tcp + translateBenchmarkStatus(segment.removePrefix("tcp "), words)
            }
            else -> segment
        }
    }
    return translated.takeIf { changed && it != text }
}

private fun translateBenchmarkStatus(status: String, words: GeneratedBenchmarkWords): String {
    Regex("^([0-9]+(?:\\.[0-9]+)?)ms$").matchEntire(status)?.let {
        return "${it.groupValues[1]} ${words.millisUnit}"
    }
    return words.statuses[status] ?: status
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
