package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonColors
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import com.kardinal.vpncontrol.MainUiState

@Composable
fun ScreenHeaderCard(
    title: String,
    description: String,
    modifier: Modifier = Modifier,
    footer: (@Composable () -> Unit)? = null,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = title,
                color = Color.White,
                fontSize = 30.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = description,
                color = Color(0xFFD3E3EE),
            )
            footer?.invoke()
        }
    }
}

@Composable
fun StatusCard(
    state: MainUiState,
    activeProfileLabel: String,
    extraDetails: List<String> = emptyList(),
    modifier: Modifier = Modifier,
) {
    val strings = LocalAppStrings.current
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(strings.get(UiText.STATUS), color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(state.statusMessage, color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(4.dp))
            Text(strings.format(UiText.SELECTED_PROFILE, activeProfileLabel), color = Color(0xFFD3E3EE))
            if (state.selectedProfileName.isNotBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    strings.format(UiText.SELECTED_LOCATION, state.selectedProfileName),
                    color = Color(0xFFD3E3EE),
                )
                Text(strings.format(UiText.SERVER, state.selectedProfileServer), color = Color(0xFFD3E3EE))
            }
            extraDetails.forEach { detail ->
                if (detail.isNotBlank()) {
                    Text(detail, color = Color(0xFFD3E3EE))
                }
            }
        }
    }
}

@Composable
fun SubscriptionMismatchWarningCard(
    activeProfileLabel: String,
    modifier: Modifier = Modifier,
) {
    val strings = LocalAppStrings.current
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(3.dp, Color(0xFFFFC857)),
        colors = CardDefaults.cardColors(containerColor = Color(0x66421F0A)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(
                text = strings.get(UiText.MISMATCH_TITLE),
                color = Color.White,
                fontWeight = FontWeight.Bold,
                fontSize = 16.sp,
            )
            Text(
                text = strings.format(UiText.MISMATCH_ACTIVE_PROFILE, activeProfileLabel),
                color = Color(0xFFFFD98A),
                fontWeight = FontWeight.SemiBold,
                fontSize = 13.sp,
            )
            Text(
                text = strings.get(UiText.MISMATCH_ACTION),
                color = Color(0xFFFFF0CC),
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
fun MainActionButton(
    icon: ImageVector,
    label: String,
    sublabel: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    outlined: Boolean = false,
    colors: ButtonColors? = null,
) {
    val content: @Composable () -> Unit = {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                modifier = Modifier.size(28.dp),
            )
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(label, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Text(sublabel)
            }
        }
    }
    if (outlined) {
        OutlinedButton(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.fillMaxWidth(),
            contentPadding = PaddingValues(18.dp),
            shape = RoundedCornerShape(22.dp),
            border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
            colors = ButtonDefaults.outlinedButtonColors(
                contentColor = Color.White,
                disabledContentColor = Color(0xFF94A9B8),
            ),
        ) {
            content()
        }
    } else {
        Button(
            onClick = onClick,
            enabled = enabled,
            modifier = modifier.fillMaxWidth(),
            contentPadding = PaddingValues(18.dp),
            shape = RoundedCornerShape(22.dp),
            colors = colors ?: ButtonDefaults.buttonColors(),
        ) {
            content()
        }
    }
}

@Composable
fun darkButtonColors() = ButtonDefaults.buttonColors(
    containerColor = Color(0xFF1D4E8C),
    contentColor = Color.White,
    disabledContainerColor = Color(0x552C4E6E),
    disabledContentColor = Color(0xFF94A9B8),
)

@Composable
fun activeVpnButtonColors() = ButtonDefaults.buttonColors(
    containerColor = Color(0xFF2E8A5E),
    contentColor = Color.White,
    disabledContainerColor = Color(0x553B7E63),
    disabledContentColor = Color(0xFFB8D1C1),
)
