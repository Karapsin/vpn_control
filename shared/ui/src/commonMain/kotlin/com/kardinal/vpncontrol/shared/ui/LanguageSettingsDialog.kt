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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
                Column(
                    modifier = Modifier
                        .heightIn(max = 440.dp)
                        .verticalScroll(rememberScrollState())
                        .padding(bottom = 8.dp),
                ) {
                    displayLanguages.forEach { language ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
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
            TextButton(onClick = onDismiss) {
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
