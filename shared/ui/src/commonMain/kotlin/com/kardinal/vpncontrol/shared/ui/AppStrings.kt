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
        localizedFreeformTextSupplement(language, trimmed)?.let { return it }
        return when (language) {
            AppLanguage.RUSSIAN -> trimmed.toRussianStatusMessage()
            AppLanguage.GERMAN,
            AppLanguage.CHINESE,
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH -> trimmed.toTranslatedStatusMessage(language)
            else -> trimmed
        }
    }
}

private fun localizedStructuredStatusMessage(
    language: AppLanguage,
    status: StructuredStatusMessage,
): String {
    fun arg(index: Int): String = status.args.getOrNull(index).orEmpty()
    return when (status.key) {
        StatusMessageKey.IDLE -> when (language) {
            AppLanguage.RUSSIAN -> "Ожидание"
            AppLanguage.GERMAN -> "Bereit"
            AppLanguage.CHINESE -> "空闲"
            AppLanguage.SPANISH -> "Inactivo"
            AppLanguage.PORTUGUESE -> "Ocioso"
            AppLanguage.FRENCH -> "Inactif"
            else -> "Idle"
        }
        StatusMessageKey.LANGUAGE_SET -> localizedLanguageSetStatus(language, arg(0))
        StatusMessageKey.SUBSCRIPTION_AUTO_REFRESH_SET ->
            localizedRefreshStatus(language, arg(0), arg(1).toIntOrNull())
        StatusMessageKey.VALIDATION_SETTINGS_SAVED ->
            localizedValidationSettingsSaved(language, arg(0), arg(1), arg(2), arg(3))
        StatusMessageKey.CUSTOM_DNS_SAVED -> when (language) {
            AppLanguage.RUSSIAN -> "Пользовательский DNS сохранен"
            AppLanguage.GERMAN -> "Benutzerdefiniertes DNS gespeichert"
            AppLanguage.CHINESE -> "自定义 DNS 已保存"
            AppLanguage.SPANISH -> "DNS personalizado guardado"
            AppLanguage.PORTUGUESE -> "DNS personalizado salvo"
            AppLanguage.FRENCH -> "DNS personnalisé enregistré"
            else -> "Custom DNS saved"
        }
        StatusMessageKey.CUSTOM_DNS_DISABLED -> when (language) {
            AppLanguage.RUSSIAN -> "Пользовательский DNS отключен"
            AppLanguage.GERMAN -> "Benutzerdefiniertes DNS deaktiviert"
            AppLanguage.CHINESE -> "自定义 DNS 已禁用"
            AppLanguage.SPANISH -> "DNS personalizado desactivado"
            AppLanguage.PORTUGUESE -> "DNS personalizado desativado"
            AppLanguage.FRENCH -> "DNS personnalisé désactivé"
            else -> "Custom DNS disabled"
        }
        StatusMessageKey.FIND_BEST_FROM_SUBSCRIPTION ->
            generatedStatusTranslations[language]?.dynamic?.findingSubscription
                ?: "Finding the best location from the subscription..."
        StatusMessageKey.FIND_BEST_FROM_SAVED ->
            generatedStatusTranslations[language]?.dynamic?.findingSaved
                ?: "Finding the best location from saved locations..."
        StatusMessageKey.STARTING_CONNECTION -> localizedStartingConnection(language, arg(0), withBestLocation = false)
        StatusMessageKey.STARTING_CONNECTION_WITH_BEST -> localizedStartingConnection(language, arg(0), withBestLocation = true)
        StatusMessageKey.CONNECTION_STARTED -> localizedConnectionStarted(language, arg(0))
        StatusMessageKey.CONNECTION_STOPPED -> localizedConnectionStopped(language, arg(0))
        StatusMessageKey.CONNECTION_READY_ON_COMPUTER -> localizedConnectionReadyOnComputer(language, arg(0))
        StatusMessageKey.DESKTOP_APP_INITIALIZED -> when (language) {
            AppLanguage.RUSSIAN -> "Приложение запущено"
            AppLanguage.GERMAN -> "App gestartet"
            AppLanguage.CHINESE -> "应用已启动"
            AppLanguage.SPANISH -> "App iniciada"
            AppLanguage.PORTUGUESE -> "App iniciada"
            AppLanguage.FRENCH -> "App démarrée"
            else -> "App initialized"
        }
        StatusMessageKey.RUNTIME_MODE -> localizedRuntimeMode(language, arg(0))
        StatusMessageKey.LOCAL_PROXY -> localizedLocalProxy(language, arg(0))
        StatusMessageKey.RUNTIME_LOG -> localizedRuntimeLog(language, arg(0))
        StatusMessageKey.PREFLIGHT_PASSED -> localizedPreflightPassed(language, arg(0))
        StatusMessageKey.PREFLIGHT_FAILED -> localizedPreflightFailed(language, arg(0), arg(1).toIntOrNull() ?: 0)
        StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY -> when (language) {
            AppLanguage.RUSSIAN -> "VPN на компьютере: готово"
            AppLanguage.GERMAN -> "VPN auf diesem Computer: bereit"
            AppLanguage.CHINESE -> "这台电脑上的 VPN：就绪"
            AppLanguage.SPANISH -> "VPN en este equipo: lista"
            AppLanguage.PORTUGUESE -> "VPN neste computador: pronta"
            AppLanguage.FRENCH -> "VPN sur cet ordinateur : prêt"
            else -> "Desktop VPN capability: ready"
        }
        StatusMessageKey.DESKTOP_VPN_CAPABILITY_ERROR -> localizedDesktopVpnCapabilityError(language, arg(0))
    }
}

private fun localizedLanguageSetStatus(language: AppLanguage, languageName: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> "Язык: ${languageName.ifBlank { "системный" }}"
        AppLanguage.GERMAN -> "Sprache: ${languageName.ifBlank { "Systemstandard" }}"
        AppLanguage.CHINESE -> "语言：${languageName.ifBlank { "系统默认" }}"
        AppLanguage.SPANISH -> "Idioma: ${languageName.ifBlank { "predeterminado del sistema" }}"
        AppLanguage.PORTUGUESE -> "Idioma: ${languageName.ifBlank { "padrão do sistema" }}"
        AppLanguage.FRENCH -> "Langue : ${languageName.ifBlank { "valeur système" }}"
        else -> "Language set to ${languageName.ifBlank { "system default" }}"
    }
}

private fun localizedRefreshStatus(
    language: AppLanguage,
    policyName: String,
    intervalMinutes: Int?,
): String {
    val value = when {
        policyName == SubscriptionRefreshPolicy.OFF.name -> localizedOff(language)
        intervalMinutes != null -> formatLocalizedRefreshInterval(intervalMinutes, language, includeEvery = true)
        policyName == SubscriptionRefreshPolicy.EVERY_HOUR.name -> formatLocalizedRefreshInterval(60, language, includeEvery = true)
        else -> when (language) {
            AppLanguage.RUSSIAN -> "свой интервал"
            AppLanguage.GERMAN -> "benutzerdefiniertes Intervall"
            AppLanguage.CHINESE -> "自定义间隔"
            AppLanguage.SPANISH -> "intervalo personalizado"
            AppLanguage.PORTUGUESE -> "intervalo personalizado"
            AppLanguage.FRENCH -> "intervalle personnalisé"
            else -> "custom interval"
        }
    }
    return when (language) {
        AppLanguage.RUSSIAN -> "Автообновление подписки: $value"
        AppLanguage.GERMAN -> "Abo-Autoaktualisierung: $value"
        AppLanguage.CHINESE -> "订阅自动刷新：$value"
        AppLanguage.SPANISH -> "Actualización automática de suscripción: $value"
        AppLanguage.PORTUGUESE -> "Atualização automática da assinatura: $value"
        AppLanguage.FRENCH -> "Actualisation automatique de l'abonnement : $value"
        else -> "Subscription auto-refresh set to $value"
    }
}

private fun localizedValidationSettingsSaved(
    language: AppLanguage,
    primary: String,
    secondary: String,
    batchSize: String,
    retryCount: String,
): String {
    val summary = when (language) {
        AppLanguage.RUSSIAN -> "$primary • $secondary • группа $batchSize • повторные попытки $retryCount"
        AppLanguage.GERMAN -> "$primary • $secondary • Gruppe $batchSize • Wiederholungen $retryCount"
        AppLanguage.CHINESE -> "$primary • $secondary • 组大小 $batchSize • 重试 $retryCount"
        AppLanguage.SPANISH -> "$primary • $secondary • lote $batchSize • reintentos $retryCount"
        AppLanguage.PORTUGUESE -> "$primary • $secondary • lote $batchSize • tentativas $retryCount"
        AppLanguage.FRENCH -> "$primary • $secondary • lot $batchSize • relances $retryCount"
        else -> "$primary • $secondary • batch $batchSize • retries $retryCount"
    }
    return when (language) {
        AppLanguage.RUSSIAN -> "Настройки проверки сохранены: $summary"
        AppLanguage.GERMAN -> "Testeinstellungen gespeichert: $summary"
        AppLanguage.CHINESE -> "验证设置已保存：$summary"
        AppLanguage.SPANISH -> "Ajustes de validación guardados: $summary"
        AppLanguage.PORTUGUESE -> "Configurações de validação salvas: $summary"
        AppLanguage.FRENCH -> "Paramètres de validation enregistrés : $summary"
        else -> "Validation settings saved: $summary"
    }
}

private fun localizedStartingConnection(
    language: AppLanguage,
    mode: String,
    withBestLocation: Boolean,
): String {
    val isProxy = mode.isProxyMode()
    return when (language) {
        AppLanguage.RUSSIAN -> when {
            withBestLocation && isProxy -> "Запуск локального прокси с лучшей локацией..."
            withBestLocation -> "Запуск VPN с лучшей локацией..."
            isProxy -> "Запуск локального прокси..."
            else -> "Запуск VPN..."
        }
        AppLanguage.GERMAN -> when {
            withBestLocation && isProxy -> "Lokaler Proxy mit bestem Standort wird gestartet..."
            withBestLocation -> "VPN mit bestem Standort wird gestartet..."
            isProxy -> "Lokaler Proxy wird gestartet..."
            else -> "VPN wird gestartet..."
        }
        AppLanguage.CHINESE -> when {
            withBestLocation && isProxy -> "正在用最佳节点启动本地代理..."
            withBestLocation -> "正在用最佳节点启动 VPN..."
            isProxy -> "正在启动本地代理..."
            else -> "正在启动 VPN..."
        }
        AppLanguage.SPANISH -> when {
            withBestLocation && isProxy -> "Iniciando proxy local con la mejor ubicación..."
            withBestLocation -> "Iniciando VPN con la mejor ubicación..."
            isProxy -> "Iniciando proxy local..."
            else -> "Iniciando VPN..."
        }
        AppLanguage.PORTUGUESE -> when {
            withBestLocation && isProxy -> "Iniciando proxy local com a melhor localização..."
            withBestLocation -> "Iniciando VPN com a melhor localização..."
            isProxy -> "Iniciando proxy local..."
            else -> "Iniciando VPN..."
        }
        AppLanguage.FRENCH -> when {
            withBestLocation && isProxy -> "Démarrage du proxy local avec le meilleur emplacement..."
            withBestLocation -> "Démarrage du VPN avec le meilleur emplacement..."
            isProxy -> "Démarrage du proxy local..."
            else -> "Démarrage du VPN..."
        }
        else -> when {
            withBestLocation && isProxy -> "Starting local proxy with the best location..."
            withBestLocation -> "Starting VPN with the best location..."
            isProxy -> "Starting local proxy..."
            else -> "Starting VPN..."
        }
    }
}

private fun localizedConnectionStarted(language: AppLanguage, mode: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> if (mode.isProxyMode()) "Прокси запущен" else "VPN запущен"
        AppLanguage.GERMAN -> if (mode.isProxyMode()) "Proxy gestartet" else "VPN gestartet"
        AppLanguage.CHINESE -> if (mode.isProxyMode()) "代理已启动" else "VPN 已启动"
        AppLanguage.SPANISH -> if (mode.isProxyMode()) "Proxy iniciado" else "VPN iniciada"
        AppLanguage.PORTUGUESE -> if (mode.isProxyMode()) "Proxy iniciado" else "VPN iniciada"
        AppLanguage.FRENCH -> if (mode.isProxyMode()) "Proxy démarré" else "VPN démarré"
        else -> if (mode.isProxyMode()) "Proxy started" else "VPN started"
    }
}

private fun localizedConnectionStopped(language: AppLanguage, mode: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> if (mode.isProxyMode()) "Прокси остановлен" else "VPN остановлен"
        AppLanguage.GERMAN -> if (mode.isProxyMode()) "Proxy gestoppt" else "VPN gestoppt"
        AppLanguage.CHINESE -> if (mode.isProxyMode()) "代理已停止" else "VPN 已停止"
        AppLanguage.SPANISH -> if (mode.isProxyMode()) "Proxy detenido" else "VPN detenida"
        AppLanguage.PORTUGUESE -> if (mode.isProxyMode()) "Proxy parado" else "VPN parada"
        AppLanguage.FRENCH -> if (mode.isProxyMode()) "Proxy arrêté" else "VPN arrêté"
        else -> if (mode.isProxyMode()) "Proxy stopped" else "VPN stopped"
    }
}

private fun localizedConnectionReadyOnComputer(language: AppLanguage, mode: String): String {
    val proxy = mode.isProxyMode()
    return when (language) {
        AppLanguage.RUSSIAN -> if (proxy) "Прокси на компьютере готов" else "VPN на компьютере готов"
        AppLanguage.GERMAN -> if (proxy) "Proxy auf diesem Computer bereit" else "VPN auf diesem Computer bereit"
        AppLanguage.CHINESE -> if (proxy) "这台电脑上的代理已就绪" else "这台电脑上的 VPN 已就绪"
        AppLanguage.SPANISH -> if (proxy) "Proxy listo en este equipo" else "VPN lista en este equipo"
        AppLanguage.PORTUGUESE -> if (proxy) "Proxy pronto neste computador" else "VPN pronta neste computador"
        AppLanguage.FRENCH -> if (proxy) "Proxy prêt sur cet ordinateur" else "VPN prêt sur cet ordinateur"
        else -> if (proxy) "Proxy ready on this computer" else "VPN ready on this computer"
    }
}

private fun localizedRuntimeMode(language: AppLanguage, mode: String): String {
    val value = localizedConnectionDisplay(language, mode)
    return when (language) {
        AppLanguage.RUSSIAN -> "Текущий режим: $value"
        AppLanguage.GERMAN -> "Aktiver Modus: $value"
        AppLanguage.CHINESE -> "运行模式：$value"
        AppLanguage.SPANISH -> "Modo actual: $value"
        AppLanguage.PORTUGUESE -> "Modo atual: $value"
        AppLanguage.FRENCH -> "Mode actuel : $value"
        else -> "Runtime mode: $value"
    }
}

private fun localizedLocalProxy(language: AppLanguage, address: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> "Локальный прокси: $address"
        AppLanguage.GERMAN -> "Lokaler Proxy: $address"
        AppLanguage.CHINESE -> "本地代理：$address"
        AppLanguage.SPANISH -> "Proxy local: $address"
        AppLanguage.PORTUGUESE -> "Proxy local: $address"
        AppLanguage.FRENCH -> "Proxy local : $address"
        else -> "Local proxy: $address"
    }
}

private fun localizedRuntimeLog(language: AppLanguage, path: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> "Журнал работы: $path"
        AppLanguage.GERMAN -> "Protokolldatei: $path"
        AppLanguage.CHINESE -> "运行日志：$path"
        AppLanguage.SPANISH -> "Registro de actividad: $path"
        AppLanguage.PORTUGUESE -> "Registro de atividade: $path"
        AppLanguage.FRENCH -> "Journal d'activité : $path"
        else -> "Runtime log: $path"
    }
}

private fun localizedPreflightPassed(language: AppLanguage, mode: String): String {
    val value = localizedConnectionDisplay(language, mode)
    return when (language) {
        AppLanguage.RUSSIAN -> "Проверка режима $value пройдена"
        AppLanguage.GERMAN -> "Prüfung für $value-Modus bestanden"
        AppLanguage.CHINESE -> "$value 模式检查已通过"
        AppLanguage.SPANISH -> "Comprobación del modo $value superada"
        AppLanguage.PORTUGUESE -> "Verificação do modo $value aprovada"
        AppLanguage.FRENCH -> "Vérification du mode $value réussie"
        else -> "$value mode preflight passed"
    }
}

private fun localizedPreflightFailed(language: AppLanguage, mode: String, failedChecks: Int): String {
    val value = localizedConnectionDisplay(language, mode)
    val checks = when (language) {
        AppLanguage.RUSSIAN -> "$failedChecks проверок"
        AppLanguage.GERMAN -> "$failedChecks Prüfungen"
        AppLanguage.CHINESE -> "$failedChecks 项检查"
        AppLanguage.SPANISH -> "$failedChecks comprobaciones"
        AppLanguage.PORTUGUESE -> "$failedChecks verificações"
        AppLanguage.FRENCH -> "$failedChecks vérifications"
        else -> "$failedChecks check${if (failedChecks == 1) "" else "s"}"
    }
    return when (language) {
        AppLanguage.RUSSIAN -> "Проверка режима $value не пройдена: $checks"
        AppLanguage.GERMAN -> "Prüfung für $value-Modus fehlgeschlagen: $checks"
        AppLanguage.CHINESE -> "$value 模式检查失败：$checks"
        AppLanguage.SPANISH -> "Comprobación del modo $value fallida: $checks"
        AppLanguage.PORTUGUESE -> "Verificação do modo $value falhou: $checks"
        AppLanguage.FRENCH -> "Vérification du mode $value échouée : $checks"
        else -> "$value mode preflight failed: $checks"
    }
}

private fun localizedDesktopVpnCapabilityError(language: AppLanguage, detail: String): String {
    return when (language) {
        AppLanguage.RUSSIAN -> "VPN на компьютере: ${detail.ifBlank { "не готово" }}"
        AppLanguage.GERMAN -> "VPN auf diesem Computer: ${detail.ifBlank { "nicht bereit" }}"
        AppLanguage.CHINESE -> "这台电脑上的 VPN：${detail.ifBlank { "未就绪" }}"
        AppLanguage.SPANISH -> "VPN en este equipo: ${detail.ifBlank { "no lista" }}"
        AppLanguage.PORTUGUESE -> "VPN neste computador: ${detail.ifBlank { "não pronta" }}"
        AppLanguage.FRENCH -> "VPN sur cet ordinateur : ${detail.ifBlank { "pas prêt" }}"
        else -> "Desktop VPN capability: ${detail.ifBlank { "not ready" }}"
    }
}

private fun localizedConnectionDisplay(language: AppLanguage, mode: String): String {
    val proxy = mode.isProxyMode()
    return when {
        !proxy -> "VPN"
        language == AppLanguage.CHINESE -> "代理"
        else -> "Proxy"
    }
}

private fun localizedOff(language: AppLanguage): String {
    return when (language) {
        AppLanguage.RUSSIAN -> "выключено"
        AppLanguage.GERMAN -> "aus"
        AppLanguage.CHINESE -> "关闭"
        AppLanguage.SPANISH -> "apagado"
        AppLanguage.PORTUGUESE -> "desligado"
        AppLanguage.FRENCH -> "désactivé"
        else -> "off"
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
    fun baseLabel(): String = when (language) {
        AppLanguage.RUSSIAN -> when {
            normalizedMinutes < 60 -> "$normalizedMinutes мин"
            remainingMinutes == 0 -> "$hours ч"
            else -> "$hours ч $remainingMinutes мин"
        }
        AppLanguage.GERMAN -> when {
            normalizedMinutes < 60 -> "$normalizedMinutes Min."
            remainingMinutes == 0 -> "$hours Std."
            else -> "$hours Std. $remainingMinutes Min."
        }
        AppLanguage.CHINESE -> when {
            normalizedMinutes < 60 -> "$normalizedMinutes 分钟"
            remainingMinutes == 0 -> "$hours 小时"
            else -> "$hours 小时 $remainingMinutes 分钟"
        }
        AppLanguage.SPANISH,
        AppLanguage.PORTUGUESE,
        AppLanguage.FRENCH,
        -> when {
            normalizedMinutes < 60 -> "$normalizedMinutes min"
            remainingMinutes == 0 -> "$hours h"
            else -> "$hours h $remainingMinutes min"
        }
        else -> when {
            normalizedMinutes < 60 -> "$normalizedMinutes minute" + if (normalizedMinutes == 1) "" else "s"
            remainingMinutes == 0 -> "$hours hour" + if (hours == 1) "" else "s"
            else -> "$hours h $remainingMinutes min"
        }
    }
    val label = baseLabel()
    return if (!includeEvery) {
        label
    } else {
        when (language) {
            AppLanguage.RUSSIAN -> when {
                normalizedMinutes == 60 -> "каждый час"
                else -> "каждые $label"
            }
            AppLanguage.GERMAN -> "alle $label"
            AppLanguage.CHINESE -> "每 $label"
            AppLanguage.SPANISH -> "cada $label"
            AppLanguage.PORTUGUESE -> "a cada $label"
            AppLanguage.FRENCH -> "toutes les $label"
            else -> "every $label"
        }
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

private val russianStatusPatterns: List<Pair<Regex, (MatchResult) -> String>> = listOf(
    Regex("^Language set to (.+)$") to { "Язык: ${it.groupValues[1]}" },
    Regex("^Subscription auto-refresh set to (.+)$") to {
        "Автообновление подписки: ${it.groupValues[1].toRussianStatusValue()}"
    },
    Regex("^Validation settings saved: (.+)$") to {
        "Настройки проверки сохранены: ${it.groupValues[1].toRussianValidationSummary()}"
    },
    Regex("^Preparing (VPN|proxy)$") to { "Подготовка ${it.groupValues[1].toRussianConnectionNoun()}" },
    Regex("^(VPN|Proxy) start cancelled$") to { "Запуск ${it.groupValues[1].toRussianConnectionDisplay()} отменен" },
    Regex("^(VPN|Proxy) stop cancelled$") to { "Остановка ${it.groupValues[1].toRussianConnectionDisplay()} отменена" },
    Regex("^Failed to stop (VPN|proxy)$") to { "Не удалось остановить ${it.groupValues[1].toRussianConnectionNoun()}" },
    Regex("^Failed to start (VPN|proxy)$") to { "Не удалось запустить ${it.groupValues[1].toRussianConnectionNoun()}" },
    Regex("^Could not prepare (VPN|proxy)$") to { "Не удалось подготовить ${it.groupValues[1].toRussianConnectionNoun()}" },
    Regex("^Best location selected and (vpn|proxy) started: (.+)$") to {
        "Выбрана лучшая локация, ${it.groupValues[1].toRussianConnectionNoun()} запущен: ${it.groupValues[2]}"
    },
    Regex("^Selected location set: (.+)$") to { "Выбрана локация: ${it.groupValues[1]}" },
    Regex("^Selected location unchanged: (.+)$") to { "Выбранная локация не изменилась: ${it.groupValues[1]}" },
    Regex("^Selected location removed: (.+)$") to { "Выбранная локация удалена: ${it.groupValues[1]}" },
    Regex("^Selected location removed\\. (VPN|Proxy) stopped: (.+)$") to {
        "Выбранная локация удалена. ${it.groupValues[1].toRussianConnectionDisplay()} остановлен: ${it.groupValues[2]}"
    },
    Regex("^Location added: (.+)$") to { "Локация добавлена: ${it.groupValues[1]}" },
    Regex("^Location updated: (.+)$") to { "Локация обновлена: ${it.groupValues[1]}" },
    Regex("^Location updated and merged: (.+)$") to { "Локация обновлена и объединена: ${it.groupValues[1]}" },
    Regex("^Location removed: (.+)$") to { "Локация удалена: ${it.groupValues[1]}" },
    Regex("^Location already saved: (.+)$") to { "Локация уже сохранена: ${it.groupValues[1]}" },
    Regex("^Locations imported\\. Selected location is no longer available, (vpn|proxy) stopped$") to {
        "Локации импортированы. Выбранная локация больше недоступна, ${it.groupValues[1].toRussianConnectionNoun()} остановлен"
    },
    Regex("^Routing rules saved\\. Restart (VPN|proxy) to apply$") to {
        "Правила маршрутизации сохранены. Перезапустите ${it.groupValues[1].toRussianConnectionNoun()}, чтобы применить"
    },
    Regex("^Routing rules imported\\. Restart (VPN|proxy) to apply$") to {
        "Правила маршрутизации импортированы. Перезапустите ${it.groupValues[1].toRussianConnectionNoun()}, чтобы применить"
    },
    Regex("^Subscriptions refreshed: (\\d+)/(\\d+)$") to {
        "Подписки обновлены: ${it.groupValues[1]}/${it.groupValues[2]}"
    },
    Regex("^Subscriptions refreshed: (\\d+)/(\\d+)\\. Failed: (.+)$") to {
        "Подписки обновлены: ${it.groupValues[1]}/${it.groupValues[2]}. Ошибки: ${it.groupValues[3]}"
    },
    Regex("^(\\d+) locations refreshed$") to { "Локаций обновлено: ${it.groupValues[1]}" },
    Regex("^Refreshing (.+)\\.\\.\\.$") to { "Обновление ${it.groupValues[1]}..." },
    Regex("^Restoring VPN: (.+)\\.\\.\\.$") to { "Восстановление VPN: ${it.groupValues[1]}..." },
    Regex("^VPN started on (.+)$") to { "VPN запущен на ${it.groupValues[1]}" },
    Regex("^Proxy started on (.+)$") to { "Прокси запущен на ${it.groupValues[1]}" },
    Regex("^(VPN|Proxy) stopped\\. Will reconnect on next launch\\.$") to {
        "${it.groupValues[1].toRussianConnectionDisplay()} остановлен. Подключение будет восстановлено при следующем запуске."
    },
    Regex("^(VPN|Proxy) stopped\\. App mode: (.+)$") to {
        "${it.groupValues[1].toRussianConnectionDisplay()} остановлен. Режим приложения: ${it.groupValues[2]}"
    },
    Regex("^(VPN|Proxy) stopped\\. Refreshed subscriptions removed the selected location\\.$") to {
        "${it.groupValues[1].toRussianConnectionDisplay()} остановлен. Обновленные подписки удалили выбранную локацию."
    },
    Regex("^Failed to stop (VPN|Proxy) before exit$") to {
        "Не удалось остановить ${it.groupValues[1].toRussianConnectionDisplay()} перед выходом"
    },
    Regex("^Failed to start (VPN|Proxy)$") to { "Не удалось запустить ${it.groupValues[1].toRussianConnectionDisplay()}" },
    Regex("^Failed to select location$") to { "Не удалось выбрать локацию" },
    Regex("^Failed to save selected location$") to { "Не удалось сохранить выбранную локацию" },
    Regex("^Failed to apply selected location$") to { "Не удалось применить выбранную локацию" },
    Regex("^Selected location applied, but failed to save it$") to {
        "Выбранная локация применена, но сохранить ее не удалось"
    },
    Regex("^Failed to load apps$") to { "Не удалось загрузить приложения" },
    Regex("^Failed to refresh subscriptions$") to { "Не удалось обновить подписки" },
    Regex("^Failed to refresh the active subscription$") to { "Не удалось обновить активную подписку" },
    Regex("^Failed to import routing rules$") to { "Не удалось импортировать правила маршрутизации" },
    Regex("^Failed to save routing rules$") to { "Не удалось сохранить правила маршрутизации" },
    Regex("^Failed to import locations$") to { "Не удалось импортировать локации" },
    Regex("^Failed to open locations file$") to { "Не удалось открыть файл локаций" },
    Regex("^Failed to read locations file$") to { "Не удалось прочитать файл локаций" },
    Regex("^Failed to open routing rules file$") to { "Не удалось открыть файл правил маршрутизации" },
    Regex("^Clipboard read failed$") to { "Не удалось прочитать буфер обмена" },
    Regex("^No locations to export$") to { "Нет локаций для экспорта" },
    Regex("^Locations exported to (.+)$") to { "Локации экспортированы в ${it.groupValues[1]}" },
    Regex("^Routing rules exported to (.+)$") to { "Правила маршрутизации экспортированы в ${it.groupValues[1]}" },
    Regex("^Diagnostics exported to (.+)$") to { "Диагностика экспортирована в ${it.groupValues[1]}" },
    Regex("^Activated (.+)$") to { "Активировано: ${it.groupValues[1]}" },
    Regex("^Added (.+)$") to { "Добавлено: ${it.groupValues[1]}" },
    Regex("^Deleted (.+)$") to { "Удалено: ${it.groupValues[1]}" },
    Regex("^Edited location #(\\d+)$") to { "Локация #${it.groupValues[1]} отредактирована" },
    Regex("^Selected (.+)$") to { "Выбрано: ${it.groupValues[1]}" },
    Regex("^App mode: (.+)$") to { "Режим приложения: ${it.groupValues[1]}" },
)

private fun String.toRussianStatusMessage(): String {
    generatedStatusTranslations[AppLanguage.RUSSIAN]?.legacyExact?.get(this)?.let { return it }
    russianStatusPatterns.forEach { (regex, formatter) ->
        regex.matchEntire(this)?.let { return formatter(it) }
    }
    return toRussianValidationSummary()
}

private fun String.toRussianValidationSummary(): String {
    return replace(" • batch ", " • группа ")
        .replace(" • retries ", " • повторные попытки ")
}

private fun String.toRussianStatusValue(): String {
    return when (lowercase()) {
        "off" -> "выключено"
        "every hour" -> "каждый час"
        "custom interval" -> "свой интервал"
        "all subscriptions" -> "все подписки"
        "selected subscription" -> "выбранная подписка"
        else -> replace("custom interval", "свой интервал")
            .replace("every hour", "каждый час")
            .replace("off", "выключено")
            .replaceEnglishRefreshIntervals(AppLanguage.RUSSIAN)
    }
}

private fun String.toRussianConnectionNoun(): String {
    return when (lowercase()) {
        "proxy" -> "прокси"
        else -> "VPN"
    }
}

private fun String.toRussianConnectionDisplay(): String {
    return when (lowercase()) {
        "proxy" -> "Прокси"
        else -> "VPN"
    }
}

private fun String.toTranslatedStatusMessage(language: AppLanguage): String {
    val replacements = generatedStatusTranslations[language]?.legacyReplacements ?: return this
    val translated = replacements.fold(this) { current, (source, target) ->
        current.replace(source, target)
    }
    return translated.replaceEnglishRefreshIntervals(language)
}

private fun String.replaceEnglishRefreshIntervals(language: AppLanguage): String {
    return Regex("\\bevery (\\d+) h (\\d+) min\\b").replace(this) { match ->
        val minutes = match.groupValues[1].toInt() * 60 + match.groupValues[2].toInt()
        formatLocalizedRefreshInterval(minutes, language, includeEvery = true)
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
