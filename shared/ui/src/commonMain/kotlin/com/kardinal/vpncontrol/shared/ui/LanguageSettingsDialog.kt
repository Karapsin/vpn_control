package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.model.AppLanguage

@Composable
fun LanguageSettingsDialog(
    selectedLanguage: AppLanguage,
    systemLanguageCode: String?,
    onSelectLanguage: (AppLanguage) -> Unit,
    onDismiss: () -> Unit,
) {
    val strings = LocalAppStrings.current
    val displayLanguages = sortedLanguageOptions(strings, systemLanguageCode)
    var searchQuery by remember { mutableStateOf("") }
    val filteredLanguages = filteredLanguageOptions(
        languages = displayLanguages,
        strings = strings,
        systemLanguageCode = systemLanguageCode,
        query = searchQuery,
    )
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(strings.get(UiText.SETTINGS_LANGUAGE_DIALOG_TITLE), color = Color.White) },
        containerColor = Color(0xFF141F2D),
        textContentColor = Color.White,
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    text = strings.get(UiText.SETTINGS_LANGUAGE_DIALOG_DESCRIPTION),
                    color = Color(0xFFD3E3EE),
                    fontSize = 13.sp,
                )
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier.fillMaxWidth().testTag("language-search"),
                    label = { Text(strings.get(UiText.SETTINGS_LANGUAGE)) },
                    leadingIcon = {
                        Icon(
                            imageVector = Icons.Filled.Search,
                            contentDescription = null,
                        )
                    },
                    singleLine = true,
                )
                Column(
                    modifier = Modifier
                        .heightIn(max = 440.dp)
                        .verticalScroll(rememberScrollState())
                        .padding(bottom = 8.dp),
                ) {
                    filteredLanguages.forEach { language ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag(
                                    when (language) {
                                        AppLanguage.SYSTEM -> "language-system"
                                        AppLanguage.ENGLISH -> "language-en"
                                        else -> "language-${language.code}"
                                    },
                                )
                                .clickable { onSelectLanguage(language) }
                                .padding(vertical = 6.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            RadioButton(
                                selected = selectedLanguage == language,
                                onClick = { onSelectLanguage(language) },
                            )
                            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(
                                    text = strings.languageDisplayName(language, systemLanguageCode),
                                    color = Color.White,
                                    fontWeight = FontWeight.SemiBold,
                                )
                                if (language != AppLanguage.SYSTEM) {
                                    Text(
                                        text = language.code,
                                        color = Color(0xFFD3E3EE),
                                        fontSize = 12.sp,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-close")) {
                Text(strings.get(UiText.CLOSE), color = Color(0xFFD3E3EE))
            }
        },
    )
}

internal fun sortedLanguageOptions(
    strings: AppStrings,
    systemLanguageCode: String?,
): List<AppLanguage> {
    val sortedLanguages = AppLanguage.selectable
        .filterNot { it == AppLanguage.SYSTEM }
        .sortedBy { strings.languageDisplayName(it, systemLanguageCode).lowercase() }
    return listOf(AppLanguage.SYSTEM) + sortedLanguages
}

internal fun filteredLanguageOptions(
    languages: List<AppLanguage>,
    strings: AppStrings,
    systemLanguageCode: String?,
    query: String,
): List<AppLanguage> {
    val normalizedQuery = query.trim().lowercase()
    if (normalizedQuery.isBlank()) return languages
    return languages.filter { language ->
        listOf(
            strings.languageDisplayName(language, systemLanguageCode),
            language.nativeName,
            language.code,
            language.name,
            language.name.replace('_', ' '),
        ).any { value -> value.lowercase().contains(normalizedQuery) }
    }
}
