package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.StructuredStatusMessage
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy

internal fun localizedStructuredStatusMessage(
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
        StatusMessageKey.CONNECTION_START_CANCELLED,
        StatusMessageKey.CONNECTION_STOP_CANCELLED,
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
        StatusMessageKey.PROFILE_SOURCE_SET,
        StatusMessageKey.FIND_BEST_TESTING_FASTEST -> "${status.key.name}.${profileSource(0)}"
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
    return token.toIntOrNull()?.let { localizedStatusArg(language, arg(it)) } ?: when (token) {
        "refreshInterval" -> structuredRefreshInterval(language, status)
        "checkCount" -> structuredCheckCount(language, arg(1).toIntOrNull() ?: 0)
        "valueOrNotReady" -> arg(0).ifBlank {
            localizedGeneratedStatusMessage(language, "not ready") ?: "not ready"
        }
        else -> null
    } ?: renderStructuredNamedPlaceholder(language, status, token)
}

private fun localizedStatusArg(language: AppLanguage, value: String): String {
    val decoded = StatusMessages.decode(value) ?: return value
    return localizedStructuredStatusMessage(language, decoded)
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
    fun searchSourceLabel(value: String): String = when (value) {
        "ALL_SUBSCRIPTIONS" -> ui(UiText.ALL_SUBSCRIPTIONS)
        "SELECTED_SUBSCRIPTION" -> ui(UiText.ACTIVE_SUBSCRIPTION)
        "SAVED_LOCATIONS" -> ui(UiText.SAVED_LOCATIONS)
        else -> value
    }

    val parts = token.split(':')
    return when (parts.firstOrNull()) {
        "ui" -> parts.getOrNull(1)
            ?.let { runCatching { UiText.valueOf(it) }.getOrNull() }
            ?.let(::ui)
        "modeLabel" -> parts.getOrNull(1)?.toIntOrNull()?.let { modeLabel(arg(it)) }
        "connectionLabel" -> parts.getOrNull(1)?.toIntOrNull()?.let { connectionLabel(arg(it)) }
        "searchSourceLabel" -> parts.getOrNull(1)?.toIntOrNull()?.let { searchSourceLabel(arg(it)) }
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

internal fun localizedDynamicStatusMessage(language: AppLanguage, text: String): String? {
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

internal fun localizedBenchmarkMessage(language: AppLanguage, text: String): String? {
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

internal fun formatLocalizedRefreshInterval(
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
