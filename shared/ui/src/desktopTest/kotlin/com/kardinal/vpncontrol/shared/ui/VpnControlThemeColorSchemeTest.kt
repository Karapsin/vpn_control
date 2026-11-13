package com.kardinal.vpncontrol.shared.ui

import androidx.compose.material3.AlertDialogDefaults
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuDefaults
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.AbstractApplier
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Composition
import androidx.compose.runtime.Recomposer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * UI-001 and UI-002: every color a Material component can read comes from the fixed palette.
 *
 * The visual review of f31ab987 found dropdown menus painted #211F26 and the update dialog
 * #2B2930: Material's default dark `surfaceContainer` and `surfaceContainerHigh`, which the
 * scheme had left undefined. Material's own [darkColorScheme] supplies the defaults here, so a
 * role that a later Material version adds is compared too.
 */
class VpnControlThemeColorSchemeTest {
    @Test
    fun noColorRoleIsLeftAtTheMaterialDefault() {
        val app = colorRoles(inTheme { MaterialTheme.colorScheme })
        val material = colorRoles(darkColorScheme())
        assertEquals(material.keys, app.keys)
        val known = listOf("primary", "surface", "surfaceContainer", "surfaceContainerHigh")
        assertTrue(app.size >= 36 && app.keys.containsAll(known), "ColorScheme roles were not enumerated: ${app.keys}")
        val leaked = app.filter { (role, color) -> color == material.getValue(role) }
        assertTrue(
            leaked.isEmpty(),
            "Color roles still at the Material 3 dark default: " + leaked.map { (role, color) -> "$role=${color.hex()}" },
        )
    }

    @Test
    fun everyColorRoleIsAFixedPaletteColor() {
        val palette = paletteColors()
        assertTrue(palette.size >= 16 && palette.keys.containsAll(listOf("Surface", "SurfaceElevated")), "$palette")
        val foreign = colorRoles(inTheme { MaterialTheme.colorScheme })
            .filterValues { color -> color.copy(alpha = 1f) !in palette.values }
        assertTrue(
            foreign.isEmpty(),
            "Color roles outside VpnControlColors: " + foreign.map { (role, color) -> "$role=${color.hex()}" },
        )
    }

    @Test
    fun menusAndDialogsResolveToTheContractSurfaces() {
        assertEquals(
            mapOf("dropdown menu" to ELEVATED_SURFACE, "dialog" to BASE_SURFACE),
            mapOf(
                "dropdown menu" to inTheme { MenuDefaults.containerColor }.hex(),
                "dialog" to inTheme { AlertDialogDefaults.containerColor }.hex(),
            ),
        )
    }

    @Test
    fun anUncheckedSwitchTrackIsAContractSurface() {
        val colors = inTheme { SwitchDefaults.colors() }
        assertEquals(ELEVATED_SURFACE, colors.uncheckedTrackColor.hex())
        assertEquals("#FF4B7BE5", colors.checkedTrackColor.hex())
    }

    private companion object {
        // UI-002, written out so that a changed palette constant cannot move the expectation with it.
        const val BASE_SURFACE = "#FF141F2D"
        const val ELEVATED_SURFACE = "#FF1D2B3B"
    }
}

/** Reads a value the way a component does: in a composition under [VpnControlTheme]. */
private fun <T : Any> inTheme(read: @Composable () -> T): T {
    val recomposer = Recomposer(EmptyCoroutineContext)
    val composition = Composition(NoNodes(), recomposer)
    try {
        var value: T? = null
        composition.setContent { VpnControlTheme { value = read() } }
        return checkNotNull(value) { "VpnControlTheme did not compose its content" }
    } finally {
        composition.dispose()
        recomposer.cancel()
    }
}

/** The theme only provides composition locals, so the composition needs no UI nodes. */
private class NoNodes : AbstractApplier<Unit>(Unit) {
    override fun insertTopDown(index: Int, instance: Unit) = Unit
    override fun insertBottomUp(index: Int, instance: Unit) = Unit
    override fun remove(index: Int, count: Int) = Unit
    override fun move(from: Int, to: Int, count: Int) = Unit
    override fun onClear() = Unit
}

/** Every `Color` property of [owner]; a `Color` getter returns its packed value as a `long`. */
private fun colorProperties(owner: Any): Map<String, Color> = owner.javaClass.methods
    .filter { it.parameterCount == 0 && it.returnType == Long::class.javaPrimitiveType && it.name.startsWith("get") }
    .associate { getter ->
        getter.name.removePrefix("get").substringBefore('-') to Color((getter.invoke(owner) as Long).toULong())
    }

private fun colorRoles(scheme: ColorScheme): Map<String, Color> =
    colorProperties(scheme).mapKeys { (role, _) -> role.replaceFirstChar(Char::lowercase) }

private fun paletteColors(): Map<String, Color> = colorProperties(VpnControlColors)

private fun Color.hex(): String = "#%08X".format(toArgb())
