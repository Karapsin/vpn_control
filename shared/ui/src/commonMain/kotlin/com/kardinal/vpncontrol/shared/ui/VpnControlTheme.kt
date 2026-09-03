package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/** The fixed VPN Control palette. Light and dynamic-color variants are intentionally unsupported. */
object VpnControlColors {
    val Navy950 = Color(0xFF08111F)
    val Navy800 = Color(0xFF12304B)
    val Navy700 = Color(0xFF16496B)
    val Surface = Color(0xFF141F2D)
    val SurfaceElevated = Color(0xFF1D2B3B)
    val Primary = Color(0xFF4B7BE5)
    val Accent = Color(0xFF9ED6FF)
    val TextPrimary = Color(0xFFFFFFFF)
    val TextSecondary = Color(0xFFD3E3EE)
    val TextMuted = Color(0xFF94A9B8)

    // Semantic colors are the only non-blue hues in the application palette.
    val Success = Color(0xFF2E8A5E)
    val Warning = Color(0xFFFFC857)
    val Error = Color(0xFFFF6B6B)
    val OnSuccess = Color(0xFFFFFFFF)
    val OnWarning = Color(0xFF241600)
    val OnError = Color(0xFFFFFFFF)

    val AppBackground = Brush.verticalGradient(
        colors = listOf(Navy950, Navy800, Navy700),
    )
}

private val VpnControlColorScheme = darkColorScheme(
    primary = VpnControlColors.Primary,
    onPrimary = VpnControlColors.Navy950,
    primaryContainer = VpnControlColors.Navy700,
    onPrimaryContainer = VpnControlColors.TextPrimary,
    secondary = VpnControlColors.Accent,
    onSecondary = VpnControlColors.Navy950,
    secondaryContainer = VpnControlColors.Navy800,
    onSecondaryContainer = VpnControlColors.TextPrimary,
    tertiary = VpnControlColors.Accent,
    onTertiary = VpnControlColors.Navy950,
    background = VpnControlColors.Navy950,
    onBackground = VpnControlColors.TextPrimary,
    surface = VpnControlColors.Surface,
    onSurface = VpnControlColors.TextPrimary,
    surfaceVariant = VpnControlColors.SurfaceElevated,
    onSurfaceVariant = VpnControlColors.TextSecondary,
    outline = VpnControlColors.TextMuted,
    outlineVariant = VpnControlColors.Navy700,
    error = VpnControlColors.Error,
    onError = VpnControlColors.OnError,
    errorContainer = VpnControlColors.Error.copy(alpha = 0.24f),
    onErrorContainer = VpnControlColors.TextPrimary,
    scrim = VpnControlColors.Navy950,
)

private val VpnControlShapes = Shapes(
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(18.dp),
    large = RoundedCornerShape(24.dp),
)

@Composable
fun VpnControlTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = VpnControlColorScheme,
        shapes = VpnControlShapes,
        content = content,
    )
}
