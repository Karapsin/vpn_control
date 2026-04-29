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
            dynamicStatusWords(language)?.findingSubscription ?: "Finding the best location from the subscription..."
        StatusMessageKey.FIND_BEST_FROM_SAVED ->
            dynamicStatusWords(language)?.findingSaved ?: "Finding the best location from saved locations..."
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

private data class DynamicStatusWords(
    val findingSubscription: String,
    val findingSaved: String,
    val testingFastestCandidates: String,
    val checkingLocations: (String) -> String,
)

private fun localizedDynamicStatusMessage(language: AppLanguage, text: String): String? {
    val words = dynamicStatusWords(language) ?: return null
    Regex("^Checking (\\d+) locations\\.\\.\\.$").matchEntire(text)?.let {
        return words.checkingLocations(it.groupValues[1])
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

private fun dynamicStatusWords(language: AppLanguage): DynamicStatusWords? {
    return when (language) {
        AppLanguage.RUSSIAN -> DynamicStatusWords(
            findingSubscription = "Поиск лучшей локации из подписки...",
            findingSaved = "Поиск лучшей сохраненной локации...",
            testingFastestCandidates = "Проверка самых быстрых кандидатов по группам...",
            checkingLocations = { count -> "Проверка локаций: $count..." },
        )
        AppLanguage.GERMAN -> DynamicStatusWords(
            findingSubscription = "Bester Standort aus dem Abo wird gesucht...",
            findingSaved = "Bester gespeicherter Standort wird gesucht...",
            testingFastestCandidates = "Schnellste Kandidaten werden gruppenweise geprüft...",
            checkingLocations = { count -> "Prüfe $count Standorte..." },
        )
        AppLanguage.CHINESE -> DynamicStatusWords(
            findingSubscription = "正在从订阅中寻找最佳节点...",
            findingSaved = "正在从已保存节点中寻找最佳节点...",
            testingFastestCandidates = "正在分批测试最快候选节点...",
            checkingLocations = { count -> "正在检查 $count 个节点..." },
        )
        AppLanguage.SPANISH -> DynamicStatusWords(
            findingSubscription = "Buscando la mejor ubicación de la suscripción...",
            findingSaved = "Buscando la mejor ubicación guardada...",
            testingFastestCandidates = "Probando los candidatos más rápidos por lotes...",
            checkingLocations = { count -> "Comprobando $count ubicaciones..." },
        )
        AppLanguage.PORTUGUESE -> DynamicStatusWords(
            findingSubscription = "Procurando a melhor localização da assinatura...",
            findingSaved = "Procurando a melhor localização salva...",
            testingFastestCandidates = "Testando os candidatos mais rápidos em lotes...",
            checkingLocations = { count -> "Verificando $count localizações..." },
        )
        AppLanguage.FRENCH -> DynamicStatusWords(
            findingSubscription = "Recherche du meilleur emplacement dans l'abonnement...",
            findingSaved = "Recherche du meilleur emplacement enregistré...",
            testingFastestCandidates = "Test des candidats les plus rapides par lots...",
            checkingLocations = { count -> "Vérification de $count emplacements..." },
        )
        else -> null
    }
}

private data class BenchmarkWords(
    val best: String,
    val primary: String,
    val secondary: String,
    val tcp: String,
    val millisUnit: String,
    val statuses: Map<String, String>,
)

private fun localizedBenchmarkMessage(language: AppLanguage, text: String): String? {
    val words = benchmarkWords(language) ?: return null
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

private fun benchmarkWords(language: AppLanguage): BenchmarkWords? {
    return when (language) {
        AppLanguage.RUSSIAN -> BenchmarkWords(
            best = "Лучшая локация: ",
            primary = "основной тест: ",
            secondary = "резервный тест: ",
            tcp = "TCP: ",
            millisUnit = "мс",
            statuses = mapOf(
                "ok" to "успешно",
                "timeout" to "тайм-аут",
                "error" to "ошибка",
                "partial" to "частично",
                "blocked" to "заблокировано",
                "challenge" to "проверка",
                "manual" to "вручную",
                "cached" to "из кэша",
                "unreachable" to "недоступно",
                "validation_timeout" to "тайм-аут проверки",
                "tcp_timeout" to "тайм-аут TCP",
                "tcp_error" to "ошибка TCP",
                "custom_config_manual_only" to "только ручная проверка",
            ),
        )
        AppLanguage.GERMAN -> BenchmarkWords(
            best = "Bester Standort: ",
            primary = "Primärtest: ",
            secondary = "Sekundärtest: ",
            tcp = "TCP: ",
            millisUnit = "ms",
            statuses = mapOf(
                "ok" to "OK",
                "timeout" to "Zeitlimit",
                "error" to "Fehler",
                "partial" to "teilweise",
                "blocked" to "blockiert",
                "challenge" to "Prüfung",
                "manual" to "manuell",
                "cached" to "aus Cache",
                "unreachable" to "nicht erreichbar",
                "validation_timeout" to "Validierungszeitlimit",
                "tcp_timeout" to "TCP-Zeitlimit",
                "tcp_error" to "TCP-Fehler",
                "custom_config_manual_only" to "nur manuelle Prüfung",
            ),
        )
        AppLanguage.CHINESE -> BenchmarkWords(
            best = "最佳节点：",
            primary = "主测试：",
            secondary = "备用测试：",
            tcp = "TCP：",
            millisUnit = "毫秒",
            statuses = mapOf(
                "ok" to "正常",
                "timeout" to "超时",
                "error" to "错误",
                "partial" to "部分可用",
                "blocked" to "被阻止",
                "challenge" to "验证",
                "manual" to "手动",
                "cached" to "缓存",
                "unreachable" to "不可达",
                "validation_timeout" to "验证超时",
                "tcp_timeout" to "TCP 超时",
                "tcp_error" to "TCP 错误",
                "custom_config_manual_only" to "仅手动检查",
            ),
        )
        AppLanguage.SPANISH -> BenchmarkWords(
            best = "Mejor ubicación: ",
            primary = "prueba principal: ",
            secondary = "prueba secundaria: ",
            tcp = "TCP: ",
            millisUnit = "ms",
            statuses = mapOf(
                "ok" to "correcto",
                "timeout" to "tiempo agotado",
                "error" to "error",
                "partial" to "parcial",
                "blocked" to "bloqueado",
                "challenge" to "verificación",
                "manual" to "manual",
                "cached" to "en caché",
                "unreachable" to "inalcanzable",
                "validation_timeout" to "tiempo de validación agotado",
                "tcp_timeout" to "tiempo TCP agotado",
                "tcp_error" to "error TCP",
                "custom_config_manual_only" to "solo comprobación manual",
            ),
        )
        AppLanguage.PORTUGUESE -> BenchmarkWords(
            best = "Melhor localização: ",
            primary = "teste primário: ",
            secondary = "teste secundário: ",
            tcp = "TCP: ",
            millisUnit = "ms",
            statuses = mapOf(
                "ok" to "OK",
                "timeout" to "tempo esgotado",
                "error" to "erro",
                "partial" to "parcial",
                "blocked" to "bloqueado",
                "challenge" to "verificação",
                "manual" to "manual",
                "cached" to "em cache",
                "unreachable" to "inacessível",
                "validation_timeout" to "tempo de validação esgotado",
                "tcp_timeout" to "tempo TCP esgotado",
                "tcp_error" to "erro TCP",
                "custom_config_manual_only" to "apenas verificação manual",
            ),
        )
        AppLanguage.FRENCH -> BenchmarkWords(
            best = "Meilleur emplacement : ",
            primary = "test principal : ",
            secondary = "test secondaire : ",
            tcp = "TCP : ",
            millisUnit = "ms",
            statuses = mapOf(
                "ok" to "OK",
                "timeout" to "délai dépassé",
                "error" to "erreur",
                "partial" to "partiel",
                "blocked" to "bloqué",
                "challenge" to "vérification",
                "manual" to "manuel",
                "cached" to "en cache",
                "unreachable" to "inaccessible",
                "validation_timeout" to "délai de validation dépassé",
                "tcp_timeout" to "délai TCP dépassé",
                "tcp_error" to "erreur TCP",
                "custom_config_manual_only" to "vérification manuelle uniquement",
            ),
        )
        else -> null
    }
}

private fun translateBenchmarkStatus(status: String, words: BenchmarkWords): String {
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

private val russianStatusExact = mapOf(
    "Idle" to "Ожидание",
    "VPN started" to "VPN запущен",
    "VPN stopped" to "VPN остановлен",
    "Proxy started" to "Прокси запущен",
    "Proxy stopped" to "Прокси остановлен",
    "Starting VPN..." to "Запуск VPN...",
    "Starting local proxy..." to "Запуск локального прокси...",
    "Starting VPN with the best location..." to "Запуск VPN с лучшей локацией...",
    "Starting local proxy with the best location..." to "Запуск локального прокси с лучшей локацией...",
    "Finding the best location from the subscription..." to "Поиск лучшей локации из подписки...",
    "Finding the best location from saved locations..." to "Поиск лучшей сохраненной локации...",
    "Location search cancelled" to "Поиск локации отменен",
    "Location search failed" to "Поиск локации не удался",
    "Grant VPN permission and try again" to "Разрешите VPN и попробуйте снова",
    "Set a remote source first" to "Сначала укажите удаленный источник",
    "Add at least one saved location first" to "Сначала добавьте хотя бы одну сохраненную локацию",
    "Select a location first" to "Сначала выберите локацию",
    "No subscriptions saved yet" to "Сохраненных подписок пока нет",
    "Refreshing all subscriptions..." to "Обновление всех подписок...",
    "Refreshing active subscription..." to "Обновление активной подписки...",
    "Refreshing subscription..." to "Обновление подписки...",
    "Refreshing subscriptions..." to "Обновление подписок...",
    "Auto-refreshing subscription..." to "Автообновление подписки...",
    "Auto-refreshing subscriptions..." to "Автообновление подписок...",
    "Subscription refreshed" to "Подписка обновлена",
    "Subscriptions refreshed" to "Подписки обновлены",
    "Active subscription refreshed" to "Активная подписка обновлена",
    "All subscriptions refreshed" to "Все подписки обновлены",
    "Refresh failed" to "Обновление не удалось",
    "Profile source set to subscription" to "Источник профиля: подписка",
    "Profile source set to saved locations" to "Источник профиля: сохраненные локации",
    "Connection mode set to VPN" to "Режим подключения: VPN",
    "Connection mode set to proxy only" to "Режим подключения: только прокси",
    "Disconnect first to change connection mode" to "Сначала отключитесь, чтобы изменить режим подключения",
    "History entry deleted" to "Запись истории удалена",
    "Subscription name reset" to "Название подписки сброшено",
    "Subscription name saved" to "Название подписки сохранено",
    "Language set to system default" to "Язык: системный",
    "Custom DNS saved" to "Пользовательский DNS сохранен",
    "Custom DNS disabled" to "Пользовательский DNS отключен",
    "Routing rules saved" to "Правила маршрутизации сохранены",
    "Routing rules imported" to "Правила маршрутизации импортированы",
    "Locations imported" to "Локации импортированы",
    "Locations imported. Selected location is no longer available" to "Локации импортированы. Выбранная локация больше недоступна",
    "Switch to Saved Locations to import locations" to "Переключитесь на сохраненные локации, чтобы импортировать локации",
    "Switch to Saved Locations to add locations manually" to "Переключитесь на сохраненные локации, чтобы добавить локации вручную",
    "Invalid location config" to "Некорректная конфигурация локации",
    "Location to edit is no longer available" to "Редактируемая локация больше недоступна",
    "Diagnostics export opened" to "Экспорт диагностики открыт",
    "Diagnostics export failed" to "Экспорт диагностики не удался",
    "Diagnostics export canceled" to "Экспорт диагностики отменен",
    "Previous VPN location is no longer available" to "Предыдущая VPN-локация больше недоступна",
    "App closed. VPN was off." to "Приложение закрыто. VPN был выключен.",
    "Activated all subscriptions" to "Активированы все подписки",
    "All subscriptions selected" to "Выбраны все подписки",
    "Subscription selected" to "Подписка выбрана",
    "Locations copied to clipboard" to "Локации скопированы в буфер обмена",
    "Locations export canceled" to "Экспорт локаций отменен",
    "Routing rules copied to clipboard" to "Правила маршрутизации скопированы в буфер обмена",
    "Routing rules export canceled" to "Экспорт правил маршрутизации отменен",
)

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
    russianStatusExact[this]?.let { return it }
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
    val replacements = localizedStatusReplacements[language] ?: return this
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

private val localizedStatusReplacements: Map<AppLanguage, List<Pair<String, String>>> = mapOf(
    AppLanguage.GERMAN to listOf(
        "Subscription locations are read-only. Switch to Saved Locations to save edits." to "Abo-Standorte sind schreibgeschützt. Wechseln Sie zu Gespeicherte Standorte, um Änderungen zu speichern.",
        "Subscription locations are read-only. Switch to Saved Locations to delete them." to "Abo-Standorte sind schreibgeschützt. Wechseln Sie zu Gespeicherte Standorte, um sie zu löschen.",
        "Subscription received. Review and save it on the Profile tab." to "Abo empfangen. Prüfen und speichern Sie es im Tab Profil.",
        "Subscription link received. Review and save it on the Profile tab." to "Abo-Link empfangen. Prüfen und speichern Sie ihn im Tab Profil.",
        "Location config received. Review and save it on the Locations tab." to "Standortkonfiguration empfangen. Prüfen und speichern Sie sie im Tab Standorte.",
        "Starting local proxy with the best location..." to "Lokaler Proxy mit bestem Standort wird gestartet...",
        "Starting VPN with the best location..." to "VPN mit bestem Standort wird gestartet...",
        "Finding the best location from the subscription..." to "Bester Standort aus dem Abo wird gesucht...",
        "Finding the best location from saved locations..." to "Bester gespeicherter Standort wird gesucht...",
        "Locations imported. Selected location is no longer available, proxy stopped" to "Standorte importiert. Der ausgewählte Standort ist nicht mehr verfügbar, Proxy gestoppt",
        "Locations imported. Selected location is no longer available, vpn stopped" to "Standorte importiert. Der ausgewählte Standort ist nicht mehr verfügbar, VPN gestoppt",
        "Locations imported. Selected location is no longer available" to "Standorte importiert. Der ausgewählte Standort ist nicht mehr verfügbar",
        "Selected location applied, but failed to save it" to "Ausgewählter Standort angewendet, konnte aber nicht gespeichert werden",
        "Location removal rolled back because the proxy could not be stopped" to "Entfernen des Standorts zurückgerollt, weil der Proxy nicht gestoppt werden konnte",
        "Location removal rolled back because the VPN could not be stopped" to "Entfernen des Standorts zurückgerollt, weil das VPN nicht gestoppt werden konnte",
        "Locations import rolled back because the proxy could not be stopped" to "Import der Standorte zurückgerollt, weil der Proxy nicht gestoppt werden konnte",
        "Locations import rolled back because the VPN could not be stopped" to "Import der Standorte zurückgerollt, weil das VPN nicht gestoppt werden konnte",
        "VPN stopped. Refreshed subscriptions removed the selected location." to "VPN gestoppt. Aktualisierte Abos haben den ausgewählten Standort entfernt.",
        "Proxy stopped. Refreshed subscriptions removed the selected location." to "Proxy gestoppt. Aktualisierte Abos haben den ausgewählten Standort entfernt.",
        "VPN stopped. Will reconnect on next launch." to "VPN gestoppt. Verbindung wird beim nächsten Start wiederhergestellt.",
        "Proxy stopped. Will reconnect on next launch." to "Proxy gestoppt. Verbindung wird beim nächsten Start wiederhergestellt.",
        "Routing rules saved. Restart VPN to apply" to "Routing-Regeln gespeichert. Starten Sie das VPN neu, um sie anzuwenden",
        "Routing rules saved. Restart proxy to apply" to "Routing-Regeln gespeichert. Starten Sie den Proxy neu, um sie anzuwenden",
        "Routing rules imported. Restart VPN to apply" to "Routing-Regeln importiert. Starten Sie das VPN neu, um sie anzuwenden",
        "Routing rules imported. Restart proxy to apply" to "Routing-Regeln importiert. Starten Sie den Proxy neu, um sie anzuwenden",
        "Selected location removed. VPN stopped: " to "Ausgewählter Standort entfernt. VPN gestoppt: ",
        "Selected location removed. Proxy stopped: " to "Ausgewählter Standort entfernt. Proxy gestoppt: ",
        "Best location selected and vpn started: " to "Bester Standort ausgewählt und VPN gestartet: ",
        "Best location selected and proxy started: " to "Bester Standort ausgewählt und Proxy gestartet: ",
        "VPN started, but failed to save the selected location" to "VPN gestartet, aber der ausgewählte Standort konnte nicht gespeichert werden",
        "Proxy started, but failed to save the selected location" to "Proxy gestartet, aber der ausgewählte Standort konnte nicht gespeichert werden",
        "VPN started, but failed to save the best location" to "VPN gestartet, aber der beste Standort konnte nicht gespeichert werden",
        "Proxy started, but failed to save the best location" to "Proxy gestartet, aber der beste Standort konnte nicht gespeichert werden",
        "Failed to start VPN with the best location" to "VPN konnte mit dem besten Standort nicht gestartet werden",
        "Failed to start proxy with the best location" to "Proxy konnte mit dem besten Standort nicht gestartet werden",
        "Failed to save the selected location" to "Ausgewählter Standort konnte nicht gespeichert werden",
        "Failed to save selected location" to "Ausgewählter Standort konnte nicht gespeichert werden",
        "Failed to save the best location" to "Bester Standort konnte nicht gespeichert werden",
        "Failed to apply selected location" to "Ausgewählter Standort konnte nicht angewendet werden",
        "Failed to select location" to "Standort konnte nicht ausgewählt werden",
        "Failed to stop VPN before exit" to "VPN konnte vor dem Beenden nicht gestoppt werden",
        "Failed to stop Proxy before exit" to "Proxy konnte vor dem Beenden nicht gestoppt werden",
        "Failed to stop VPN" to "VPN konnte nicht gestoppt werden",
        "Failed to stop proxy" to "Proxy konnte nicht gestoppt werden",
        "Failed to start VPN" to "VPN konnte nicht gestartet werden",
        "Failed to start proxy" to "Proxy konnte nicht gestartet werden",
        "Could not prepare VPN" to "VPN konnte nicht vorbereitet werden",
        "Could not prepare proxy" to "Proxy konnte nicht vorbereitet werden",
        "Preparing VPN" to "VPN wird vorbereitet",
        "Preparing proxy" to "Proxy wird vorbereitet",
        "VPN start cancelled" to "VPN-Start abgebrochen",
        "Proxy start cancelled" to "Proxy-Start abgebrochen",
        "VPN stop cancelled" to "VPN-Stopp abgebrochen",
        "Proxy stop cancelled" to "Proxy-Stopp abgebrochen",
        "Starting local proxy..." to "Lokaler Proxy wird gestartet...",
        "Starting VPN..." to "VPN wird gestartet...",
        "Refreshing all subscriptions..." to "Alle Abos werden aktualisiert...",
        "Refreshing active subscription..." to "Aktives Abo wird aktualisiert...",
        "Refreshing subscriptions..." to "Abos werden aktualisiert...",
        "Refreshing subscription..." to "Abo wird aktualisiert...",
        "Auto-refreshing subscriptions..." to "Abos werden automatisch aktualisiert...",
        "Auto-refreshing subscription..." to "Abo wird automatisch aktualisiert...",
        "All subscriptions refreshed" to "Alle Abos aktualisiert",
        "Active subscription refreshed" to "Aktives Abo aktualisiert",
        "Subscriptions refreshed" to "Abos aktualisiert",
        "Subscription refreshed" to "Abo aktualisiert",
        "Refresh failed" to "Aktualisierung fehlgeschlagen",
        "Location search cancelled" to "Standortsuche abgebrochen",
        "Location search failed" to "Standortsuche fehlgeschlagen",
        "Grant VPN permission and try again" to "VPN-Berechtigung erteilen und erneut versuchen",
        "Set a remote source first" to "Zuerst eine entfernte Quelle festlegen",
        "Add at least one saved location first" to "Zuerst mindestens einen gespeicherten Standort hinzufügen",
        "Select a location first" to "Zuerst einen Standort auswählen",
        "No subscriptions saved yet" to "Noch keine Abos gespeichert",
        "Profile source set to subscription" to "Profilquelle auf Abo gesetzt",
        "Profile source set to saved locations" to "Profilquelle auf gespeicherte Standorte gesetzt",
        "Connection mode set to VPN" to "Verbindungsmodus auf VPN gesetzt",
        "Connection mode set to proxy only" to "Verbindungsmodus auf Nur Proxy gesetzt",
        "Disconnect first to change connection mode" to "Zum Ändern des Verbindungsmodus zuerst trennen",
        "History entry deleted" to "Verlaufseintrag gelöscht",
        "Subscription name reset" to "Abo-Name zurückgesetzt",
        "Subscription name saved" to "Abo-Name gespeichert",
        "Language set to system default" to "Sprache auf Systemstandard gesetzt",
        "Custom DNS saved" to "Benutzerdefiniertes DNS gespeichert",
        "Custom DNS disabled" to "Benutzerdefiniertes DNS deaktiviert",
        "Routing rules saved" to "Routing-Regeln gespeichert",
        "Routing rules imported" to "Routing-Regeln importiert",
        "Locations imported" to "Standorte importiert",
        "Switch to Saved Locations to import locations" to "Zum Importieren von Standorten zu Gespeicherte Standorte wechseln",
        "Switch to Saved Locations to add locations manually" to "Zum manuellen Hinzufügen von Standorten zu Gespeicherte Standorte wechseln",
        "Invalid location config" to "Ungültige Standortkonfiguration",
        "Location to edit is no longer available" to "Zu bearbeitender Standort ist nicht mehr verfügbar",
        "Diagnostics export opened" to "Diagnoseexport geöffnet",
        "Diagnostics export failed" to "Diagnoseexport fehlgeschlagen",
        "Diagnostics export canceled" to "Diagnoseexport abgebrochen",
        "Previous VPN location is no longer available" to "Vorheriger VPN-Standort ist nicht mehr verfügbar",
        "App closed. VPN was off." to "App geschlossen. VPN war aus.",
        "Activated all subscriptions" to "Alle Abos aktiviert",
        "All subscriptions selected" to "Alle Abos ausgewählt",
        "Subscription selected" to "Abo ausgewählt",
        "Subscription saved" to "Abo gespeichert",
        "Locations copied to clipboard" to "Standorte in die Zwischenablage kopiert",
        "Locations export canceled" to "Standortexport abgebrochen",
        "Routing rules copied to clipboard" to "Routing-Regeln in die Zwischenablage kopiert",
        "Routing rules export canceled" to "Export der Routing-Regeln abgebrochen",
        "Clipboard read failed" to "Zwischenablage konnte nicht gelesen werden",
        "No locations to export" to "Keine Standorte zum Exportieren",
        "Failed to load apps" to "Apps konnten nicht geladen werden",
        "Failed to refresh subscriptions" to "Abos konnten nicht aktualisiert werden",
        "Failed to refresh the active subscription" to "Aktives Abo konnte nicht aktualisiert werden",
        "Failed to import routing rules" to "Routing-Regeln konnten nicht importiert werden",
        "Failed to save routing rules" to "Routing-Regeln konnten nicht gespeichert werden",
        "Failed to import locations" to "Standorte konnten nicht importiert werden",
        "Failed to open locations file" to "Standortdatei konnte nicht geöffnet werden",
        "Failed to read locations file" to "Standortdatei konnte nicht gelesen werden",
        "Failed to open routing rules file" to "Datei mit Routing-Regeln konnte nicht geöffnet werden",
        "Best location could not be mapped to the desktop list" to "Bester Standort konnte nicht der Liste auf diesem Computer zugeordnet werden",
        "VPN ready on this computer" to "VPN auf diesem Computer bereit",
        "Proxy ready on this computer" to "Proxy auf diesem Computer bereit",
        "Desktop VPN shell ready" to "VPN auf diesem Computer bereit",
        "Desktop Proxy shell ready" to "Proxy auf diesem Computer bereit",
        "VPN started on " to "VPN gestartet auf ",
        "Proxy started on " to "Proxy gestartet auf ",
        "VPN stopped. App mode: " to "VPN gestoppt. App-Modus: ",
        "Proxy stopped. App mode: " to "Proxy gestoppt. App-Modus: ",
        "Language set to " to "Sprache: ",
        "Subscription auto-refresh set to " to "Abo-Autoaktualisierung: ",
        "Validation settings saved: " to "Testeinstellungen gespeichert: ",
        "Selected location unchanged: " to "Ausgewählter Standort unverändert: ",
        "Selected location removed: " to "Ausgewählter Standort entfernt: ",
        "Selected location set: " to "Ausgewählter Standort: ",
        "Location updated and merged: " to "Standort aktualisiert und zusammengeführt: ",
        "Location already saved: " to "Standort bereits gespeichert: ",
        "Location updated: " to "Standort aktualisiert: ",
        "Location removed: " to "Standort entfernt: ",
        "Location added: " to "Standort hinzugefügt: ",
        "Subscriptions refreshed: " to "Abos aktualisiert: ",
        "Failed: " to "Fehlgeschlagen: ",
        "Restoring VPN: " to "VPN wird wiederhergestellt: ",
        "Refreshing " to "Aktualisiere ",
        "Locations exported to " to "Standorte exportiert nach ",
        "Routing rules exported to " to "Routing-Regeln exportiert nach ",
        "Diagnostics exported to " to "Diagnose exportiert nach ",
        "Failed to benchmark " to "Benchmark fehlgeschlagen für ",
        "Activated " to "Aktiviert: ",
        "Added " to "Hinzugefügt: ",
        "Deleted " to "Gelöscht: ",
        "Selected " to "Ausgewählt: ",
        "Edited location #" to "Standort # bearbeitet: ",
        "App mode: " to "App-Modus: ",
        " locations refreshed" to " Standorte aktualisiert",
        " location refreshed" to " Standort aktualisiert",
        " • batch " to " • Gruppe ",
        " • retries " to " • Wiederholungen ",
        "custom interval" to "benutzerdefiniertes Intervall",
        "every hour" to "jede Stunde",
        "all subscriptions" to "alle Abos",
        "selected subscription" to "ausgewähltes Abo",
        "proxy only" to "nur Proxy",
        "off" to "aus",
        "Idle" to "Bereit",
        "VPN started" to "VPN gestartet",
        "VPN stopped" to "VPN gestoppt",
        "Proxy started" to "Proxy gestartet",
        "Proxy stopped" to "Proxy gestoppt",
    ),
    AppLanguage.CHINESE to listOf(
        "Subscription locations are read-only. Switch to Saved Locations to save edits." to "订阅节点为只读。请切换到已保存节点后再保存编辑。",
        "Subscription locations are read-only. Switch to Saved Locations to delete them." to "订阅节点为只读。请切换到已保存节点后再删除。",
        "Subscription received. Review and save it on the Profile tab." to "已收到订阅。请在配置页检查并保存。",
        "Subscription link received. Review and save it on the Profile tab." to "已收到订阅链接。请在配置页检查并保存。",
        "Location config received. Review and save it on the Locations tab." to "已收到节点配置。请在节点页检查并保存。",
        "Starting local proxy with the best location..." to "正在用最佳节点启动本地代理...",
        "Starting VPN with the best location..." to "正在用最佳节点启动 VPN...",
        "Finding the best location from the subscription..." to "正在从订阅中寻找最佳节点...",
        "Finding the best location from saved locations..." to "正在从已保存节点中寻找最佳节点...",
        "Locations imported. Selected location is no longer available, proxy stopped" to "节点已导入。所选节点不再可用，代理已停止",
        "Locations imported. Selected location is no longer available, vpn stopped" to "节点已导入。所选节点不再可用，VPN 已停止",
        "Locations imported. Selected location is no longer available" to "节点已导入。所选节点不再可用",
        "Selected location applied, but failed to save it" to "所选节点已应用，但保存失败",
        "Location removal rolled back because the proxy could not be stopped" to "代理无法停止，节点删除已回滚",
        "Location removal rolled back because the VPN could not be stopped" to "VPN 无法停止，节点删除已回滚",
        "Locations import rolled back because the proxy could not be stopped" to "代理无法停止，节点导入已回滚",
        "Locations import rolled back because the VPN could not be stopped" to "VPN 无法停止，节点导入已回滚",
        "VPN stopped. Refreshed subscriptions removed the selected location." to "VPN 已停止。刷新后的订阅移除了所选节点。",
        "Proxy stopped. Refreshed subscriptions removed the selected location." to "代理已停止。刷新后的订阅移除了所选节点。",
        "VPN stopped. Will reconnect on next launch." to "VPN 已停止。下次启动时会重新连接。",
        "Proxy stopped. Will reconnect on next launch." to "代理已停止。下次启动时会重新连接。",
        "Routing rules saved. Restart VPN to apply" to "路由规则已保存。重启 VPN 后生效",
        "Routing rules saved. Restart proxy to apply" to "路由规则已保存。重启代理后生效",
        "Routing rules imported. Restart VPN to apply" to "路由规则已导入。重启 VPN 后生效",
        "Routing rules imported. Restart proxy to apply" to "路由规则已导入。重启代理后生效",
        "Selected location removed. VPN stopped: " to "所选节点已删除。VPN 已停止：",
        "Selected location removed. Proxy stopped: " to "所选节点已删除。代理已停止：",
        "Best location selected and vpn started: " to "已选择最佳节点并启动 VPN：",
        "Best location selected and proxy started: " to "已选择最佳节点并启动代理：",
        "VPN started, but failed to save the selected location" to "VPN 已启动，但所选节点保存失败",
        "Proxy started, but failed to save the selected location" to "代理已启动，但所选节点保存失败",
        "VPN started, but failed to save the best location" to "VPN 已启动，但最佳节点保存失败",
        "Proxy started, but failed to save the best location" to "代理已启动，但最佳节点保存失败",
        "Failed to start VPN with the best location" to "无法用最佳节点启动 VPN",
        "Failed to start proxy with the best location" to "无法用最佳节点启动代理",
        "Failed to save the selected location" to "所选节点保存失败",
        "Failed to save selected location" to "所选节点保存失败",
        "Failed to save the best location" to "最佳节点保存失败",
        "Failed to apply selected location" to "所选节点应用失败",
        "Failed to select location" to "选择节点失败",
        "Failed to stop VPN before exit" to "退出前停止 VPN 失败",
        "Failed to stop Proxy before exit" to "退出前停止代理失败",
        "Failed to stop VPN" to "停止 VPN 失败",
        "Failed to stop proxy" to "停止代理失败",
        "Failed to start VPN" to "启动 VPN 失败",
        "Failed to start proxy" to "启动代理失败",
        "Could not prepare VPN" to "无法准备 VPN",
        "Could not prepare proxy" to "无法准备代理",
        "Preparing VPN" to "正在准备 VPN",
        "Preparing proxy" to "正在准备代理",
        "VPN start cancelled" to "VPN 启动已取消",
        "Proxy start cancelled" to "代理启动已取消",
        "VPN stop cancelled" to "VPN 停止已取消",
        "Proxy stop cancelled" to "代理停止已取消",
        "Starting local proxy..." to "正在启动本地代理...",
        "Starting VPN..." to "正在启动 VPN...",
        "Refreshing all subscriptions..." to "正在刷新所有订阅...",
        "Refreshing active subscription..." to "正在刷新当前订阅...",
        "Refreshing subscriptions..." to "正在刷新订阅...",
        "Refreshing subscription..." to "正在刷新订阅...",
        "Auto-refreshing subscriptions..." to "正在自动刷新订阅...",
        "Auto-refreshing subscription..." to "正在自动刷新订阅...",
        "All subscriptions refreshed" to "所有订阅已刷新",
        "Active subscription refreshed" to "当前订阅已刷新",
        "Subscriptions refreshed" to "订阅已刷新",
        "Subscription refreshed" to "订阅已刷新",
        "Refresh failed" to "刷新失败",
        "Location search cancelled" to "节点搜索已取消",
        "Location search failed" to "节点搜索失败",
        "Grant VPN permission and try again" to "请授予 VPN 权限后重试",
        "Set a remote source first" to "请先设置远程来源",
        "Add at least one saved location first" to "请先添加至少一个已保存节点",
        "Select a location first" to "请先选择节点",
        "No subscriptions saved yet" to "还没有保存订阅",
        "Profile source set to subscription" to "配置来源已设为订阅",
        "Profile source set to saved locations" to "配置来源已设为已保存节点",
        "Connection mode set to VPN" to "连接模式已设为 VPN",
        "Connection mode set to proxy only" to "连接模式已设为仅代理",
        "Disconnect first to change connection mode" to "请先断开连接再更改连接模式",
        "History entry deleted" to "历史记录已删除",
        "Subscription name reset" to "订阅名称已重置",
        "Subscription name saved" to "订阅名称已保存",
        "Language set to system default" to "语言已设为系统默认",
        "Custom DNS saved" to "自定义 DNS 已保存",
        "Custom DNS disabled" to "自定义 DNS 已禁用",
        "Routing rules saved" to "路由规则已保存",
        "Routing rules imported" to "路由规则已导入",
        "Locations imported" to "节点已导入",
        "Switch to Saved Locations to import locations" to "请切换到已保存节点后再导入节点",
        "Switch to Saved Locations to add locations manually" to "请切换到已保存节点后再手动添加节点",
        "Invalid location config" to "节点配置无效",
        "Location to edit is no longer available" to "要编辑的节点不再可用",
        "Diagnostics export opened" to "诊断导出已打开",
        "Diagnostics export failed" to "诊断导出失败",
        "Diagnostics export canceled" to "诊断导出已取消",
        "Previous VPN location is no longer available" to "之前的 VPN 节点不再可用",
        "App closed. VPN was off." to "应用已关闭。VPN 原本为关闭状态。",
        "Activated all subscriptions" to "已启用所有订阅",
        "All subscriptions selected" to "已选择所有订阅",
        "Subscription selected" to "订阅已选择",
        "Subscription saved" to "订阅已保存",
        "Locations copied to clipboard" to "节点已复制到剪贴板",
        "Locations export canceled" to "节点导出已取消",
        "Routing rules copied to clipboard" to "路由规则已复制到剪贴板",
        "Routing rules export canceled" to "路由规则导出已取消",
        "Clipboard read failed" to "读取剪贴板失败",
        "No locations to export" to "没有可导出的节点",
        "Failed to load apps" to "加载应用失败",
        "Failed to refresh subscriptions" to "刷新订阅失败",
        "Failed to refresh the active subscription" to "刷新当前订阅失败",
        "Failed to import routing rules" to "导入路由规则失败",
        "Failed to save routing rules" to "保存路由规则失败",
        "Failed to import locations" to "导入节点失败",
        "Failed to open locations file" to "打开节点文件失败",
        "Failed to read locations file" to "读取节点文件失败",
        "Failed to open routing rules file" to "打开路由规则文件失败",
        "Best location could not be mapped to the desktop list" to "无法将最佳节点映射到这台电脑的列表",
        "VPN ready on this computer" to "这台电脑上的 VPN 已就绪",
        "Proxy ready on this computer" to "这台电脑上的代理已就绪",
        "Desktop VPN shell ready" to "这台电脑上的 VPN 已就绪",
        "Desktop Proxy shell ready" to "这台电脑上的代理已就绪",
        "VPN started on " to "VPN 已启动于 ",
        "Proxy started on " to "代理已启动于 ",
        "VPN stopped. App mode: " to "VPN 已停止。应用模式：",
        "Proxy stopped. App mode: " to "代理已停止。应用模式：",
        "Language set to " to "语言：",
        "Subscription auto-refresh set to " to "订阅自动刷新：",
        "Validation settings saved: " to "验证设置已保存：",
        "Selected location unchanged: " to "所选节点未变化：",
        "Selected location removed: " to "所选节点已移除：",
        "Selected location set: " to "所选节点：",
        "Location updated and merged: " to "节点已更新并合并：",
        "Location already saved: " to "节点已保存：",
        "Location updated: " to "节点已更新：",
        "Location removed: " to "节点已移除：",
        "Location added: " to "节点已添加：",
        "Subscriptions refreshed: " to "订阅已刷新：",
        "Failed: " to "失败：",
        "Restoring VPN: " to "正在恢复 VPN：",
        "Refreshing " to "正在刷新 ",
        "Locations exported to " to "节点已导出到 ",
        "Routing rules exported to " to "路由规则已导出到 ",
        "Diagnostics exported to " to "诊断已导出到 ",
        "Failed to benchmark " to "测速失败：",
        "Activated " to "已启用：",
        "Added " to "已添加：",
        "Deleted " to "已删除：",
        "Selected " to "已选择：",
        "Edited location #" to "已编辑节点 #",
        "App mode: " to "应用模式：",
        " locations refreshed" to " 个节点已刷新",
        " location refreshed" to " 个节点已刷新",
        " • batch " to " • 组大小 ",
        " • retries " to " • 重试 ",
        "custom interval" to "自定义间隔",
        "every hour" to "每小时",
        "all subscriptions" to "所有订阅",
        "selected subscription" to "所选订阅",
        "proxy only" to "仅代理",
        "off" to "关闭",
        "Idle" to "空闲",
        "VPN started" to "VPN 已启动",
        "VPN stopped" to "VPN 已停止",
        "Proxy started" to "代理已启动",
        "Proxy stopped" to "代理已停止",
    ),
    AppLanguage.SPANISH to listOf(
        "Subscription locations are read-only. Switch to Saved Locations to save edits." to "Las ubicaciones de la suscripción son de solo lectura. Cambia a Ubicaciones guardadas para guardar cambios.",
        "Subscription locations are read-only. Switch to Saved Locations to delete them." to "Las ubicaciones de la suscripción son de solo lectura. Cambia a Ubicaciones guardadas para eliminarlas.",
        "Subscription received. Review and save it on the Profile tab." to "Suscripción recibida. Revísala y guárdala en la pestaña Perfil.",
        "Subscription link received. Review and save it on the Profile tab." to "Enlace de suscripción recibido. Revísalo y guárdalo en la pestaña Perfil.",
        "Location config received. Review and save it on the Locations tab." to "Configuración de ubicación recibida. Revísala y guárdala en la pestaña Ubicaciones.",
        "Starting local proxy with the best location..." to "Iniciando proxy local con la mejor ubicación...",
        "Starting VPN with the best location..." to "Iniciando VPN con la mejor ubicación...",
        "Finding the best location from the subscription..." to "Buscando la mejor ubicación de la suscripción...",
        "Finding the best location from saved locations..." to "Buscando la mejor ubicación guardada...",
        "Locations imported. Selected location is no longer available, proxy stopped" to "Ubicaciones importadas. La ubicación seleccionada ya no está disponible, proxy detenido",
        "Locations imported. Selected location is no longer available, vpn stopped" to "Ubicaciones importadas. La ubicación seleccionada ya no está disponible, VPN detenida",
        "Locations imported. Selected location is no longer available" to "Ubicaciones importadas. La ubicación seleccionada ya no está disponible",
        "Selected location applied, but failed to save it" to "Ubicación seleccionada aplicada, pero no se pudo guardar",
        "Location removal rolled back because the proxy could not be stopped" to "La eliminación de la ubicación se revirtió porque no se pudo detener el proxy",
        "Location removal rolled back because the VPN could not be stopped" to "La eliminación de la ubicación se revirtió porque no se pudo detener la VPN",
        "Locations import rolled back because the proxy could not be stopped" to "La importación de ubicaciones se revirtió porque no se pudo detener el proxy",
        "Locations import rolled back because the VPN could not be stopped" to "La importación de ubicaciones se revirtió porque no se pudo detener la VPN",
        "VPN stopped. Refreshed subscriptions removed the selected location." to "VPN detenida. Las suscripciones actualizadas eliminaron la ubicación seleccionada.",
        "Proxy stopped. Refreshed subscriptions removed the selected location." to "Proxy detenido. Las suscripciones actualizadas eliminaron la ubicación seleccionada.",
        "VPN stopped. Will reconnect on next launch." to "VPN detenida. Se reconectará en el próximo inicio.",
        "Proxy stopped. Will reconnect on next launch." to "Proxy detenido. Se reconectará en el próximo inicio.",
        "Routing rules saved. Restart VPN to apply" to "Reglas de enrutamiento guardadas. Reinicia la VPN para aplicar",
        "Routing rules saved. Restart proxy to apply" to "Reglas de enrutamiento guardadas. Reinicia el proxy para aplicar",
        "Routing rules imported. Restart VPN to apply" to "Reglas de enrutamiento importadas. Reinicia la VPN para aplicar",
        "Routing rules imported. Restart proxy to apply" to "Reglas de enrutamiento importadas. Reinicia el proxy para aplicar",
        "Selected location removed. VPN stopped: " to "Ubicación seleccionada eliminada. VPN detenida: ",
        "Selected location removed. Proxy stopped: " to "Ubicación seleccionada eliminada. Proxy detenido: ",
        "Best location selected and vpn started: " to "Mejor ubicación seleccionada y VPN iniciada: ",
        "Best location selected and proxy started: " to "Mejor ubicación seleccionada y proxy iniciado: ",
        "VPN started, but failed to save the selected location" to "VPN iniciada, pero no se pudo guardar la ubicación seleccionada",
        "Proxy started, but failed to save the selected location" to "Proxy iniciado, pero no se pudo guardar la ubicación seleccionada",
        "VPN started, but failed to save the best location" to "VPN iniciada, pero no se pudo guardar la mejor ubicación",
        "Proxy started, but failed to save the best location" to "Proxy iniciado, pero no se pudo guardar la mejor ubicación",
        "Failed to start VPN with the best location" to "No se pudo iniciar la VPN con la mejor ubicación",
        "Failed to start proxy with the best location" to "No se pudo iniciar el proxy con la mejor ubicación",
        "Failed to save the selected location" to "No se pudo guardar la ubicación seleccionada",
        "Failed to save selected location" to "No se pudo guardar la ubicación seleccionada",
        "Failed to save the best location" to "No se pudo guardar la mejor ubicación",
        "Failed to apply selected location" to "No se pudo aplicar la ubicación seleccionada",
        "Failed to select location" to "No se pudo seleccionar la ubicación",
        "Failed to stop VPN before exit" to "No se pudo detener la VPN antes de salir",
        "Failed to stop Proxy before exit" to "No se pudo detener el proxy antes de salir",
        "Failed to stop VPN" to "No se pudo detener la VPN",
        "Failed to stop proxy" to "No se pudo detener el proxy",
        "Failed to start VPN" to "No se pudo iniciar la VPN",
        "Failed to start proxy" to "No se pudo iniciar el proxy",
        "Could not prepare VPN" to "No se pudo preparar la VPN",
        "Could not prepare proxy" to "No se pudo preparar el proxy",
        "Preparing VPN" to "Preparando VPN",
        "Preparing proxy" to "Preparando proxy",
        "VPN start cancelled" to "Inicio de VPN cancelado",
        "Proxy start cancelled" to "Inicio de proxy cancelado",
        "VPN stop cancelled" to "Detención de VPN cancelada",
        "Proxy stop cancelled" to "Detención de proxy cancelada",
        "Starting local proxy..." to "Iniciando proxy local...",
        "Starting VPN..." to "Iniciando VPN...",
        "Refreshing all subscriptions..." to "Actualizando todas las suscripciones...",
        "Refreshing active subscription..." to "Actualizando suscripción activa...",
        "Refreshing subscriptions..." to "Actualizando suscripciones...",
        "Refreshing subscription..." to "Actualizando suscripción...",
        "Auto-refreshing subscriptions..." to "Actualizando suscripciones automáticamente...",
        "Auto-refreshing subscription..." to "Actualizando suscripción automáticamente...",
        "All subscriptions refreshed" to "Todas las suscripciones actualizadas",
        "Active subscription refreshed" to "Suscripción activa actualizada",
        "Subscriptions refreshed" to "Suscripciones actualizadas",
        "Subscription refreshed" to "Suscripción actualizada",
        "Refresh failed" to "Error al actualizar",
        "Location search cancelled" to "Búsqueda de ubicación cancelada",
        "Location search failed" to "Búsqueda de ubicación fallida",
        "Grant VPN permission and try again" to "Concede permiso de VPN e inténtalo de nuevo",
        "Set a remote source first" to "Primero configura una fuente remota",
        "Add at least one saved location first" to "Primero añade al menos una ubicación guardada",
        "Select a location first" to "Primero selecciona una ubicación",
        "No subscriptions saved yet" to "Aún no hay suscripciones guardadas",
        "Profile source set to subscription" to "Fuente de perfil establecida en suscripción",
        "Profile source set to saved locations" to "Fuente de perfil establecida en ubicaciones guardadas",
        "Connection mode set to VPN" to "Modo de conexión establecido en VPN",
        "Connection mode set to proxy only" to "Modo de conexión establecido en solo proxy",
        "Disconnect first to change connection mode" to "Desconecta primero para cambiar el modo de conexión",
        "History entry deleted" to "Entrada del historial eliminada",
        "Subscription name reset" to "Nombre de suscripción restablecido",
        "Subscription name saved" to "Nombre de suscripción guardado",
        "Language set to system default" to "Idioma establecido en el predeterminado del sistema",
        "Custom DNS saved" to "DNS personalizado guardado",
        "Custom DNS disabled" to "DNS personalizado desactivado",
        "Routing rules saved" to "Reglas de enrutamiento guardadas",
        "Routing rules imported" to "Reglas de enrutamiento importadas",
        "Locations imported" to "Ubicaciones importadas",
        "Switch to Saved Locations to import locations" to "Cambia a Ubicaciones guardadas para importar ubicaciones",
        "Switch to Saved Locations to add locations manually" to "Cambia a Ubicaciones guardadas para añadir ubicaciones manualmente",
        "Invalid location config" to "Configuración de ubicación no válida",
        "Location to edit is no longer available" to "La ubicación a editar ya no está disponible",
        "Diagnostics export opened" to "Exportación de diagnóstico abierta",
        "Diagnostics export failed" to "Exportación de diagnóstico fallida",
        "Diagnostics export canceled" to "Exportación de diagnóstico cancelada",
        "Previous VPN location is no longer available" to "La ubicación VPN anterior ya no está disponible",
        "App closed. VPN was off." to "Aplicación cerrada. La VPN estaba apagada.",
        "Activated all subscriptions" to "Todas las suscripciones activadas",
        "All subscriptions selected" to "Todas las suscripciones seleccionadas",
        "Subscription selected" to "Suscripción seleccionada",
        "Subscription saved" to "Suscripción guardada",
        "Locations copied to clipboard" to "Ubicaciones copiadas al portapapeles",
        "Locations export canceled" to "Exportación de ubicaciones cancelada",
        "Routing rules copied to clipboard" to "Reglas de enrutamiento copiadas al portapapeles",
        "Routing rules export canceled" to "Exportación de reglas de enrutamiento cancelada",
        "Clipboard read failed" to "No se pudo leer el portapapeles",
        "No locations to export" to "No hay ubicaciones para exportar",
        "Failed to load apps" to "No se pudieron cargar las apps",
        "Failed to refresh subscriptions" to "No se pudieron actualizar las suscripciones",
        "Failed to refresh the active subscription" to "No se pudo actualizar la suscripción activa",
        "Failed to import routing rules" to "No se pudieron importar las reglas de enrutamiento",
        "Failed to save routing rules" to "No se pudieron guardar las reglas de enrutamiento",
        "Failed to import locations" to "No se pudieron importar las ubicaciones",
        "Failed to open locations file" to "No se pudo abrir el archivo de ubicaciones",
        "Failed to read locations file" to "No se pudo leer el archivo de ubicaciones",
        "Failed to open routing rules file" to "No se pudo abrir el archivo de reglas de enrutamiento",
        "Best location could not be mapped to the desktop list" to "La mejor ubicación no se pudo asociar a la lista de este equipo",
        "VPN ready on this computer" to "VPN lista en este equipo",
        "Proxy ready on this computer" to "Proxy listo en este equipo",
        "Desktop VPN shell ready" to "VPN lista en este equipo",
        "Desktop Proxy shell ready" to "Proxy listo en este equipo",
        "VPN started on " to "VPN iniciada en ",
        "Proxy started on " to "Proxy iniciado en ",
        "VPN stopped. App mode: " to "VPN detenida. Modo de app: ",
        "Proxy stopped. App mode: " to "Proxy detenido. Modo de app: ",
        "Language set to " to "Idioma: ",
        "Subscription auto-refresh set to " to "Actualización automática de suscripción: ",
        "Validation settings saved: " to "Ajustes de validación guardados: ",
        "Selected location unchanged: " to "Ubicación seleccionada sin cambios: ",
        "Selected location removed: " to "Ubicación seleccionada eliminada: ",
        "Selected location set: " to "Ubicación seleccionada: ",
        "Location updated and merged: " to "Ubicación actualizada y combinada: ",
        "Location already saved: " to "Ubicación ya guardada: ",
        "Location updated: " to "Ubicación actualizada: ",
        "Location removed: " to "Ubicación eliminada: ",
        "Location added: " to "Ubicación añadida: ",
        "Subscriptions refreshed: " to "Suscripciones actualizadas: ",
        "Failed: " to "Fallidas: ",
        "Restoring VPN: " to "Restaurando VPN: ",
        "Refreshing " to "Actualizando ",
        "Locations exported to " to "Ubicaciones exportadas a ",
        "Routing rules exported to " to "Reglas de enrutamiento exportadas a ",
        "Diagnostics exported to " to "Diagnóstico exportado a ",
        "Failed to benchmark " to "Falló la prueba de ",
        "Activated " to "Activado: ",
        "Added " to "Añadido: ",
        "Deleted " to "Eliminado: ",
        "Selected " to "Seleccionado: ",
        "Edited location #" to "Ubicación # editada: ",
        "App mode: " to "Modo de app: ",
        " locations refreshed" to " ubicaciones actualizadas",
        " location refreshed" to " ubicación actualizada",
        " • batch " to " • lote ",
        " • retries " to " • reintentos ",
        "custom interval" to "intervalo personalizado",
        "every hour" to "cada hora",
        "all subscriptions" to "todas las suscripciones",
        "selected subscription" to "suscripción seleccionada",
        "proxy only" to "solo proxy",
        "off" to "apagado",
        "Idle" to "Inactivo",
        "VPN started" to "VPN iniciada",
        "VPN stopped" to "VPN detenida",
        "Proxy started" to "Proxy iniciado",
        "Proxy stopped" to "Proxy detenido",
    ),
    AppLanguage.PORTUGUESE to listOf(
        "Subscription locations are read-only. Switch to Saved Locations to save edits." to "As localizações da assinatura são somente leitura. Mude para Localizações salvas para salvar edições.",
        "Subscription locations are read-only. Switch to Saved Locations to delete them." to "As localizações da assinatura são somente leitura. Mude para Localizações salvas para apagá-las.",
        "Subscription received. Review and save it on the Profile tab." to "Assinatura recebida. Revise e salve na aba Perfil.",
        "Subscription link received. Review and save it on the Profile tab." to "Link de assinatura recebido. Revise e salve na aba Perfil.",
        "Location config received. Review and save it on the Locations tab." to "Configuração de localização recebida. Revise e salve na aba Localizações.",
        "Starting local proxy with the best location..." to "Iniciando proxy local com a melhor localização...",
        "Starting VPN with the best location..." to "Iniciando VPN com a melhor localização...",
        "Finding the best location from the subscription..." to "Procurando a melhor localização da assinatura...",
        "Finding the best location from saved locations..." to "Procurando a melhor localização salva...",
        "Locations imported. Selected location is no longer available, proxy stopped" to "Localizações importadas. A localização selecionada não está mais disponível, proxy parado",
        "Locations imported. Selected location is no longer available, vpn stopped" to "Localizações importadas. A localização selecionada não está mais disponível, VPN parada",
        "Locations imported. Selected location is no longer available" to "Localizações importadas. A localização selecionada não está mais disponível",
        "Selected location applied, but failed to save it" to "Localização selecionada aplicada, mas não foi possível salvá-la",
        "Location removal rolled back because the proxy could not be stopped" to "A remoção da localização foi revertida porque o proxy não pôde ser parado",
        "Location removal rolled back because the VPN could not be stopped" to "A remoção da localização foi revertida porque a VPN não pôde ser parada",
        "Locations import rolled back because the proxy could not be stopped" to "A importação de localizações foi revertida porque o proxy não pôde ser parado",
        "Locations import rolled back because the VPN could not be stopped" to "A importação de localizações foi revertida porque a VPN não pôde ser parada",
        "VPN stopped. Refreshed subscriptions removed the selected location." to "VPN parada. As assinaturas atualizadas removeram a localização selecionada.",
        "Proxy stopped. Refreshed subscriptions removed the selected location." to "Proxy parado. As assinaturas atualizadas removeram a localização selecionada.",
        "VPN stopped. Will reconnect on next launch." to "VPN parada. Vai reconectar no próximo início.",
        "Proxy stopped. Will reconnect on next launch." to "Proxy parado. Vai reconectar no próximo início.",
        "Routing rules saved. Restart VPN to apply" to "Regras de roteamento salvas. Reinicie a VPN para aplicar",
        "Routing rules saved. Restart proxy to apply" to "Regras de roteamento salvas. Reinicie o proxy para aplicar",
        "Routing rules imported. Restart VPN to apply" to "Regras de roteamento importadas. Reinicie a VPN para aplicar",
        "Routing rules imported. Restart proxy to apply" to "Regras de roteamento importadas. Reinicie o proxy para aplicar",
        "Selected location removed. VPN stopped: " to "Localização selecionada removida. VPN parada: ",
        "Selected location removed. Proxy stopped: " to "Localização selecionada removida. Proxy parado: ",
        "Best location selected and vpn started: " to "Melhor localização selecionada e VPN iniciada: ",
        "Best location selected and proxy started: " to "Melhor localização selecionada e proxy iniciado: ",
        "VPN started, but failed to save the selected location" to "VPN iniciada, mas não foi possível salvar a localização selecionada",
        "Proxy started, but failed to save the selected location" to "Proxy iniciado, mas não foi possível salvar a localização selecionada",
        "VPN started, but failed to save the best location" to "VPN iniciada, mas não foi possível salvar a melhor localização",
        "Proxy started, but failed to save the best location" to "Proxy iniciado, mas não foi possível salvar a melhor localização",
        "Failed to start VPN with the best location" to "Não foi possível iniciar a VPN com a melhor localização",
        "Failed to start proxy with the best location" to "Não foi possível iniciar o proxy com a melhor localização",
        "Failed to save the selected location" to "Não foi possível salvar a localização selecionada",
        "Failed to save selected location" to "Não foi possível salvar a localização selecionada",
        "Failed to save the best location" to "Não foi possível salvar a melhor localização",
        "Failed to apply selected location" to "Não foi possível aplicar a localização selecionada",
        "Failed to select location" to "Não foi possível selecionar a localização",
        "Failed to stop VPN before exit" to "Não foi possível parar a VPN antes de sair",
        "Failed to stop Proxy before exit" to "Não foi possível parar o proxy antes de sair",
        "Failed to stop VPN" to "Não foi possível parar a VPN",
        "Failed to stop proxy" to "Não foi possível parar o proxy",
        "Failed to start VPN" to "Não foi possível iniciar a VPN",
        "Failed to start proxy" to "Não foi possível iniciar o proxy",
        "Could not prepare VPN" to "Não foi possível preparar a VPN",
        "Could not prepare proxy" to "Não foi possível preparar o proxy",
        "Preparing VPN" to "Preparando VPN",
        "Preparing proxy" to "Preparando proxy",
        "VPN start cancelled" to "Início da VPN cancelado",
        "Proxy start cancelled" to "Início do proxy cancelado",
        "VPN stop cancelled" to "Parada da VPN cancelada",
        "Proxy stop cancelled" to "Parada do proxy cancelada",
        "Starting local proxy..." to "Iniciando proxy local...",
        "Starting VPN..." to "Iniciando VPN...",
        "Refreshing all subscriptions..." to "Atualizando todas as assinaturas...",
        "Refreshing active subscription..." to "Atualizando assinatura ativa...",
        "Refreshing subscriptions..." to "Atualizando assinaturas...",
        "Refreshing subscription..." to "Atualizando assinatura...",
        "Auto-refreshing subscriptions..." to "Atualizando assinaturas automaticamente...",
        "Auto-refreshing subscription..." to "Atualizando assinatura automaticamente...",
        "All subscriptions refreshed" to "Todas as assinaturas atualizadas",
        "Active subscription refreshed" to "Assinatura ativa atualizada",
        "Subscriptions refreshed" to "Assinaturas atualizadas",
        "Subscription refreshed" to "Assinatura atualizada",
        "Refresh failed" to "Falha ao atualizar",
        "Location search cancelled" to "Busca de localização cancelada",
        "Location search failed" to "Busca de localização falhou",
        "Grant VPN permission and try again" to "Conceda permissão de VPN e tente novamente",
        "Set a remote source first" to "Defina uma fonte remota primeiro",
        "Add at least one saved location first" to "Adicione pelo menos uma localização salva primeiro",
        "Select a location first" to "Selecione uma localização primeiro",
        "No subscriptions saved yet" to "Nenhuma assinatura salva ainda",
        "Profile source set to subscription" to "Fonte do perfil definida como assinatura",
        "Profile source set to saved locations" to "Fonte do perfil definida como localizações salvas",
        "Connection mode set to VPN" to "Modo de conexão definido como VPN",
        "Connection mode set to proxy only" to "Modo de conexão definido como somente proxy",
        "Disconnect first to change connection mode" to "Desconecte primeiro para alterar o modo de conexão",
        "History entry deleted" to "Entrada do histórico apagada",
        "Subscription name reset" to "Nome da assinatura redefinido",
        "Subscription name saved" to "Nome da assinatura salvo",
        "Language set to system default" to "Idioma definido como padrão do sistema",
        "Custom DNS saved" to "DNS personalizado salvo",
        "Custom DNS disabled" to "DNS personalizado desativado",
        "Routing rules saved" to "Regras de roteamento salvas",
        "Routing rules imported" to "Regras de roteamento importadas",
        "Locations imported" to "Localizações importadas",
        "Switch to Saved Locations to import locations" to "Mude para Localizações salvas para importar localizações",
        "Switch to Saved Locations to add locations manually" to "Mude para Localizações salvas para adicionar localizações manualmente",
        "Invalid location config" to "Configuração de localização inválida",
        "Location to edit is no longer available" to "A localização a editar não está mais disponível",
        "Diagnostics export opened" to "Exportação de diagnóstico aberta",
        "Diagnostics export failed" to "Exportação de diagnóstico falhou",
        "Diagnostics export canceled" to "Exportação de diagnóstico cancelada",
        "Previous VPN location is no longer available" to "A localização VPN anterior não está mais disponível",
        "App closed. VPN was off." to "App fechado. A VPN estava desligada.",
        "Activated all subscriptions" to "Todas as assinaturas ativadas",
        "All subscriptions selected" to "Todas as assinaturas selecionadas",
        "Subscription selected" to "Assinatura selecionada",
        "Subscription saved" to "Assinatura salva",
        "Locations copied to clipboard" to "Localizações copiadas para a área de transferência",
        "Locations export canceled" to "Exportação de localizações cancelada",
        "Routing rules copied to clipboard" to "Regras de roteamento copiadas para a área de transferência",
        "Routing rules export canceled" to "Exportação de regras de roteamento cancelada",
        "Clipboard read failed" to "Falha ao ler a área de transferência",
        "No locations to export" to "Nenhuma localização para exportar",
        "Failed to load apps" to "Não foi possível carregar apps",
        "Failed to refresh subscriptions" to "Não foi possível atualizar assinaturas",
        "Failed to refresh the active subscription" to "Não foi possível atualizar a assinatura ativa",
        "Failed to import routing rules" to "Não foi possível importar regras de roteamento",
        "Failed to save routing rules" to "Não foi possível salvar regras de roteamento",
        "Failed to import locations" to "Não foi possível importar localizações",
        "Failed to open locations file" to "Não foi possível abrir o arquivo de localizações",
        "Failed to read locations file" to "Não foi possível ler o arquivo de localizações",
        "Failed to open routing rules file" to "Não foi possível abrir o arquivo de regras de roteamento",
        "Best location could not be mapped to the desktop list" to "A melhor localização não pôde ser mapeada para a lista no computador",
        "VPN ready on this computer" to "VPN pronta neste computador",
        "Proxy ready on this computer" to "Proxy pronto neste computador",
        "Desktop VPN shell ready" to "VPN pronta neste computador",
        "Desktop Proxy shell ready" to "Proxy pronto neste computador",
        "VPN started on " to "VPN iniciada em ",
        "Proxy started on " to "Proxy iniciado em ",
        "VPN stopped. App mode: " to "VPN parada. Modo do app: ",
        "Proxy stopped. App mode: " to "Proxy parado. Modo do app: ",
        "Language set to " to "Idioma: ",
        "Subscription auto-refresh set to " to "Atualização automática da assinatura: ",
        "Validation settings saved: " to "Configurações de validação salvas: ",
        "Selected location unchanged: " to "Localização selecionada sem alteração: ",
        "Selected location removed: " to "Localização selecionada removida: ",
        "Selected location set: " to "Localização selecionada: ",
        "Location updated and merged: " to "Localização atualizada e mesclada: ",
        "Location already saved: " to "Localização já salva: ",
        "Location updated: " to "Localização atualizada: ",
        "Location removed: " to "Localização removida: ",
        "Location added: " to "Localização adicionada: ",
        "Subscriptions refreshed: " to "Assinaturas atualizadas: ",
        "Failed: " to "Falhas: ",
        "Restoring VPN: " to "Restaurando VPN: ",
        "Refreshing " to "Atualizando ",
        "Locations exported to " to "Localizações exportadas para ",
        "Routing rules exported to " to "Regras de roteamento exportadas para ",
        "Diagnostics exported to " to "Diagnóstico exportado para ",
        "Failed to benchmark " to "Falha ao testar ",
        "Activated " to "Ativado: ",
        "Added " to "Adicionado: ",
        "Deleted " to "Apagado: ",
        "Selected " to "Selecionado: ",
        "Edited location #" to "Localização # editada: ",
        "App mode: " to "Modo do app: ",
        " locations refreshed" to " localizações atualizadas",
        " location refreshed" to " localização atualizada",
        " • batch " to " • lote ",
        " • retries " to " • tentativas ",
        "custom interval" to "intervalo personalizado",
        "every hour" to "a cada hora",
        "all subscriptions" to "todas as assinaturas",
        "selected subscription" to "assinatura selecionada",
        "proxy only" to "somente proxy",
        "off" to "desligado",
        "Idle" to "Ocioso",
        "VPN started" to "VPN iniciada",
        "VPN stopped" to "VPN parada",
        "Proxy started" to "Proxy iniciado",
        "Proxy stopped" to "Proxy parado",
    ),
    AppLanguage.FRENCH to listOf(
        "Subscription locations are read-only. Switch to Saved Locations to save edits." to "Les emplacements de l'abonnement sont en lecture seule. Passez aux emplacements enregistrés pour sauvegarder les modifications.",
        "Subscription locations are read-only. Switch to Saved Locations to delete them." to "Les emplacements de l'abonnement sont en lecture seule. Passez aux emplacements enregistrés pour les supprimer.",
        "Subscription received. Review and save it on the Profile tab." to "Abonnement reçu. Vérifiez-le et enregistrez-le dans l'onglet Profil.",
        "Subscription link received. Review and save it on the Profile tab." to "Lien d'abonnement reçu. Vérifiez-le et enregistrez-le dans l'onglet Profil.",
        "Location config received. Review and save it on the Locations tab." to "Configuration d'emplacement reçue. Vérifiez-la et enregistrez-la dans l'onglet Emplacements.",
        "Starting local proxy with the best location..." to "Démarrage du proxy local avec le meilleur emplacement...",
        "Starting VPN with the best location..." to "Démarrage du VPN avec le meilleur emplacement...",
        "Finding the best location from the subscription..." to "Recherche du meilleur emplacement dans l'abonnement...",
        "Finding the best location from saved locations..." to "Recherche du meilleur emplacement enregistré...",
        "Locations imported. Selected location is no longer available, proxy stopped" to "Emplacements importés. L'emplacement sélectionné n'est plus disponible, proxy arrêté",
        "Locations imported. Selected location is no longer available, vpn stopped" to "Emplacements importés. L'emplacement sélectionné n'est plus disponible, VPN arrêté",
        "Locations imported. Selected location is no longer available" to "Emplacements importés. L'emplacement sélectionné n'est plus disponible",
        "Selected location applied, but failed to save it" to "Emplacement sélectionné appliqué, mais impossible de l'enregistrer",
        "Location removal rolled back because the proxy could not be stopped" to "Suppression de l'emplacement annulée, car le proxy n'a pas pu être arrêté",
        "Location removal rolled back because the VPN could not be stopped" to "Suppression de l'emplacement annulée, car le VPN n'a pas pu être arrêté",
        "Locations import rolled back because the proxy could not be stopped" to "Import des emplacements annulé, car le proxy n'a pas pu être arrêté",
        "Locations import rolled back because the VPN could not be stopped" to "Import des emplacements annulé, car le VPN n'a pas pu être arrêté",
        "VPN stopped. Refreshed subscriptions removed the selected location." to "VPN arrêté. Les abonnements actualisés ont supprimé l'emplacement sélectionné.",
        "Proxy stopped. Refreshed subscriptions removed the selected location." to "Proxy arrêté. Les abonnements actualisés ont supprimé l'emplacement sélectionné.",
        "VPN stopped. Will reconnect on next launch." to "VPN arrêté. Reconnexion au prochain lancement.",
        "Proxy stopped. Will reconnect on next launch." to "Proxy arrêté. Reconnexion au prochain lancement.",
        "Routing rules saved. Restart VPN to apply" to "Règles de routage enregistrées. Redémarrez le VPN pour appliquer",
        "Routing rules saved. Restart proxy to apply" to "Règles de routage enregistrées. Redémarrez le proxy pour appliquer",
        "Routing rules imported. Restart VPN to apply" to "Règles de routage importées. Redémarrez le VPN pour appliquer",
        "Routing rules imported. Restart proxy to apply" to "Règles de routage importées. Redémarrez le proxy pour appliquer",
        "Selected location removed. VPN stopped: " to "Emplacement sélectionné supprimé. VPN arrêté : ",
        "Selected location removed. Proxy stopped: " to "Emplacement sélectionné supprimé. Proxy arrêté : ",
        "Best location selected and vpn started: " to "Meilleur emplacement sélectionné et VPN démarré : ",
        "Best location selected and proxy started: " to "Meilleur emplacement sélectionné et proxy démarré : ",
        "VPN started, but failed to save the selected location" to "VPN démarré, mais l'emplacement sélectionné n'a pas pu être enregistré",
        "Proxy started, but failed to save the selected location" to "Proxy démarré, mais l'emplacement sélectionné n'a pas pu être enregistré",
        "VPN started, but failed to save the best location" to "VPN démarré, mais le meilleur emplacement n'a pas pu être enregistré",
        "Proxy started, but failed to save the best location" to "Proxy démarré, mais le meilleur emplacement n'a pas pu être enregistré",
        "Failed to start VPN with the best location" to "Impossible de démarrer le VPN avec le meilleur emplacement",
        "Failed to start proxy with the best location" to "Impossible de démarrer le proxy avec le meilleur emplacement",
        "Failed to save the selected location" to "Impossible d'enregistrer l'emplacement sélectionné",
        "Failed to save selected location" to "Impossible d'enregistrer l'emplacement sélectionné",
        "Failed to save the best location" to "Impossible d'enregistrer le meilleur emplacement",
        "Failed to apply selected location" to "Impossible d'appliquer l'emplacement sélectionné",
        "Failed to select location" to "Impossible de sélectionner l'emplacement",
        "Failed to stop VPN before exit" to "Impossible d'arrêter le VPN avant de quitter",
        "Failed to stop Proxy before exit" to "Impossible d'arrêter le proxy avant de quitter",
        "Failed to stop VPN" to "Impossible d'arrêter le VPN",
        "Failed to stop proxy" to "Impossible d'arrêter le proxy",
        "Failed to start VPN" to "Impossible de démarrer le VPN",
        "Failed to start proxy" to "Impossible de démarrer le proxy",
        "Could not prepare VPN" to "Impossible de préparer le VPN",
        "Could not prepare proxy" to "Impossible de préparer le proxy",
        "Preparing VPN" to "Préparation du VPN",
        "Preparing proxy" to "Préparation du proxy",
        "VPN start cancelled" to "Démarrage du VPN annulé",
        "Proxy start cancelled" to "Démarrage du proxy annulé",
        "VPN stop cancelled" to "Arrêt du VPN annulé",
        "Proxy stop cancelled" to "Arrêt du proxy annulé",
        "Starting local proxy..." to "Démarrage du proxy local...",
        "Starting VPN..." to "Démarrage du VPN...",
        "Refreshing all subscriptions..." to "Actualisation de tous les abonnements...",
        "Refreshing active subscription..." to "Actualisation de l'abonnement actif...",
        "Refreshing subscriptions..." to "Actualisation des abonnements...",
        "Refreshing subscription..." to "Actualisation de l'abonnement...",
        "Auto-refreshing subscriptions..." to "Actualisation automatique des abonnements...",
        "Auto-refreshing subscription..." to "Actualisation automatique de l'abonnement...",
        "All subscriptions refreshed" to "Tous les abonnements actualisés",
        "Active subscription refreshed" to "Abonnement actif actualisé",
        "Subscriptions refreshed" to "Abonnements actualisés",
        "Subscription refreshed" to "Abonnement actualisé",
        "Refresh failed" to "Échec de l'actualisation",
        "Location search cancelled" to "Recherche d'emplacement annulée",
        "Location search failed" to "Recherche d'emplacement échouée",
        "Grant VPN permission and try again" to "Accordez l'autorisation VPN et réessayez",
        "Set a remote source first" to "Définissez d'abord une source distante",
        "Add at least one saved location first" to "Ajoutez d'abord au moins un emplacement enregistré",
        "Select a location first" to "Sélectionnez d'abord un emplacement",
        "No subscriptions saved yet" to "Aucun abonnement enregistré",
        "Profile source set to subscription" to "Source du profil définie sur abonnement",
        "Profile source set to saved locations" to "Source du profil définie sur emplacements enregistrés",
        "Connection mode set to VPN" to "Mode de connexion défini sur VPN",
        "Connection mode set to proxy only" to "Mode de connexion défini sur proxy uniquement",
        "Disconnect first to change connection mode" to "Déconnectez d'abord pour changer de mode de connexion",
        "History entry deleted" to "Entrée d'historique supprimée",
        "Subscription name reset" to "Nom de l'abonnement réinitialisé",
        "Subscription name saved" to "Nom de l'abonnement enregistré",
        "Language set to system default" to "Langue définie sur la valeur système",
        "Custom DNS saved" to "DNS personnalisé enregistré",
        "Custom DNS disabled" to "DNS personnalisé désactivé",
        "Routing rules saved" to "Règles de routage enregistrées",
        "Routing rules imported" to "Règles de routage importées",
        "Locations imported" to "Emplacements importés",
        "Switch to Saved Locations to import locations" to "Passez aux emplacements enregistrés pour importer des emplacements",
        "Switch to Saved Locations to add locations manually" to "Passez aux emplacements enregistrés pour ajouter des emplacements manuellement",
        "Invalid location config" to "Configuration d'emplacement invalide",
        "Location to edit is no longer available" to "L'emplacement à modifier n'est plus disponible",
        "Diagnostics export opened" to "Export de diagnostic ouvert",
        "Diagnostics export failed" to "Échec de l'export de diagnostic",
        "Diagnostics export canceled" to "Export de diagnostic annulé",
        "Previous VPN location is no longer available" to "L'emplacement VPN précédent n'est plus disponible",
        "App closed. VPN was off." to "Application fermée. Le VPN était désactivé.",
        "Activated all subscriptions" to "Tous les abonnements activés",
        "All subscriptions selected" to "Tous les abonnements sélectionnés",
        "Subscription selected" to "Abonnement sélectionné",
        "Subscription saved" to "Abonnement enregistré",
        "Locations copied to clipboard" to "Emplacements copiés dans le presse-papiers",
        "Locations export canceled" to "Export des emplacements annulé",
        "Routing rules copied to clipboard" to "Règles de routage copiées dans le presse-papiers",
        "Routing rules export canceled" to "Export des règles de routage annulé",
        "Clipboard read failed" to "Lecture du presse-papiers échouée",
        "No locations to export" to "Aucun emplacement à exporter",
        "Failed to load apps" to "Impossible de charger les applications",
        "Failed to refresh subscriptions" to "Impossible d'actualiser les abonnements",
        "Failed to refresh the active subscription" to "Impossible d'actualiser l'abonnement actif",
        "Failed to import routing rules" to "Impossible d'importer les règles de routage",
        "Failed to save routing rules" to "Impossible d'enregistrer les règles de routage",
        "Failed to import locations" to "Impossible d'importer les emplacements",
        "Failed to open locations file" to "Impossible d'ouvrir le fichier d'emplacements",
        "Failed to read locations file" to "Impossible de lire le fichier d'emplacements",
        "Failed to open routing rules file" to "Impossible d'ouvrir le fichier de règles de routage",
        "Best location could not be mapped to the desktop list" to "Le meilleur emplacement n'a pas pu être associé à la liste ordinateur",
        "VPN ready on this computer" to "VPN prêt sur cet ordinateur",
        "Proxy ready on this computer" to "Proxy prêt sur cet ordinateur",
        "Desktop VPN shell ready" to "VPN prêt sur cet ordinateur",
        "Desktop Proxy shell ready" to "Proxy prêt sur cet ordinateur",
        "VPN started on " to "VPN démarré sur ",
        "Proxy started on " to "Proxy démarré sur ",
        "VPN stopped. App mode: " to "VPN arrêté. Mode de l'app : ",
        "Proxy stopped. App mode: " to "Proxy arrêté. Mode de l'app : ",
        "Language set to " to "Langue : ",
        "Subscription auto-refresh set to " to "Actualisation automatique de l'abonnement : ",
        "Validation settings saved: " to "Paramètres de validation enregistrés : ",
        "Selected location unchanged: " to "Emplacement sélectionné inchangé : ",
        "Selected location removed: " to "Emplacement sélectionné supprimé : ",
        "Selected location set: " to "Emplacement sélectionné : ",
        "Location updated and merged: " to "Emplacement mis à jour et fusionné : ",
        "Location already saved: " to "Emplacement déjà enregistré : ",
        "Location updated: " to "Emplacement mis à jour : ",
        "Location removed: " to "Emplacement supprimé : ",
        "Location added: " to "Emplacement ajouté : ",
        "Subscriptions refreshed: " to "Abonnements actualisés : ",
        "Failed: " to "Échecs : ",
        "Restoring VPN: " to "Restauration du VPN : ",
        "Refreshing " to "Actualisation de ",
        "Locations exported to " to "Emplacements exportés vers ",
        "Routing rules exported to " to "Règles de routage exportées vers ",
        "Diagnostics exported to " to "Diagnostic exporté vers ",
        "Failed to benchmark " to "Échec du test de ",
        "Activated " to "Activé : ",
        "Added " to "Ajouté : ",
        "Deleted " to "Supprimé : ",
        "Selected " to "Sélectionné : ",
        "Edited location #" to "Emplacement # modifié : ",
        "App mode: " to "Mode de l'app : ",
        " locations refreshed" to " emplacements actualisés",
        " location refreshed" to " emplacement actualisé",
        " • batch " to " • lot ",
        " • retries " to " • relances ",
        "custom interval" to "intervalle personnalisé",
        "every hour" to "toutes les heures",
        "all subscriptions" to "tous les abonnements",
        "selected subscription" to "abonnement sélectionné",
        "proxy only" to "proxy uniquement",
        "off" to "désactivé",
        "Idle" to "Inactif",
        "VPN started" to "VPN démarré",
        "VPN stopped" to "VPN arrêté",
        "Proxy started" to "Proxy démarré",
        "Proxy stopped" to "Proxy arrêté",
    ),
).mapValues { (_, replacements) ->
    replacements.sortedByDescending { it.first.length }
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
