package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage

internal fun localizedFreeformTextSupplement(language: AppLanguage, text: String): String? {
    val replacements = generatedStatusTranslations[language]?.freeformReplacements ?: return null
    val translated = replacements.fold(text) { current, (source, target) ->
        current.replace(source, target)
    }
    return translated.takeIf { it != text }
}
