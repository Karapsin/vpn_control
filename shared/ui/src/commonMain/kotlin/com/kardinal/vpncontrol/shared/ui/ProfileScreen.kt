package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun ProfileScreen(
    activeProfileLabel: String,
    currentSelectionLabel: String,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val strings = LocalAppStrings.current
    Scaffold(
        modifier = modifier,
        containerColor = Color(0xFF141F2D),
        contentColor = Color.White,
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 20.dp, top = 24.dp, end = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                ScreenHeaderCard(
                    title = strings.get(UiText.PROFILE_TITLE),
                    description = strings.get(UiText.PROFILE_DESCRIPTION),
                    footer = {
                        Text(
                            text = strings.format(UiText.SELECTED_PROFILE, activeProfileLabel),
                            color = Color(0xFF9ED6FF),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            text = strings.format(UiText.CURRENT_SELECTION, currentSelectionLabel),
                            color = Color(0xFFD3E3EE),
                            fontSize = 12.sp,
                        )
                    },
                )
                content()
            }
        }
    }
}
