package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage

internal fun localizedFreeformTextSupplement(language: AppLanguage, text: String): String? {
    val replacements = generatedStatusTranslations[language]?.freeformReplacements ?: return null
    val translated = replacements.fold(text) { current, (source, target) ->
        current.replace(source, target)
    }
    return translated.takeIf { it != text }
}

internal fun localizedGeneratedStatusMessage(language: AppLanguage, text: String): String? {
    val translations = generatedStatusTranslations[language] ?: return null
    translations.legacyExact[text]?.let { return it }

    val translated = (translations.legacyReplacements + translations.freeformReplacements)
        .fold(text) { current, (source, target) ->
            current.replace(source, target)
        }
        .replaceEnglishRefreshIntervals(language)
    return translated.takeIf { it != text }
}
