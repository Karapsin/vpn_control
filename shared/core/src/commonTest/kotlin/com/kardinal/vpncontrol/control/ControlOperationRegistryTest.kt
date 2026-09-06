package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlPlatform
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ControlOperationRegistryTest {
    @Test
    fun everyOperationHasOneDescriptorAndUnambiguousNames() {
        val operations = ControlOperationRegistry.operations
        assertEquals(ControlOperationId.entries.toSet(), operations.map { it.id }.toSet())
        val names = operations.flatMap { listOf(it.commandWords.joinToString(" ")) + it.aliases }
        assertEquals(names.size, names.distinct().size)
        assertEquals(operations.size, operations.map { it.coverageId }.distinct().size)
        assertTrue(operations.all { it.grammar.isNotBlank() && it.contracts.isNotEmpty() })
        assertTrue(operations.filter { it.kind == ControlActionKind.PRODUCT }.all { !it.guiAction.isNullOrBlank() })
    }

    @Test
    fun legacySelectIsAnAliasNotASecondDomainAction() {
        assertEquals(listOf("select"), ControlOperationRegistry[ControlOperationId.LOCATIONS_SELECT].aliases)
    }

    @Test
    fun platformDifferencesAreExplicitAndUnknownCapabilitiesFailClosed() {
        for (platform in ControlPlatform.entries) {
            assertEquals(platform == ControlPlatform.ANDROID, ControlOperationRegistry.platformSupports("routing.apps", platform))
            assertEquals(platform != ControlPlatform.MACOS, ControlOperationRegistry.platformSupports("mode.vpn", platform))
            assertEquals(platform != ControlPlatform.ANDROID, ControlOperationRegistry.platformSupports("desktop.lifecycle", platform))
            assertTrue(ControlOperationRegistry.platformSupports("mode.proxy-only", platform))
            assertFalse(ControlOperationRegistry.platformSupports("unknown", platform))
        }
        assertFalse(ControlOperationRegistry.platformSupports("autostart", ControlPlatform.MACOS))
        assertFalse(ControlOperationRegistry.platformSupports("autostart", ControlPlatform.ANDROID))
    }

    @Test
    fun dormantRoutingAndHiddenSettingsDoNotBecomePublicActions() {
        val ids = ControlOperationId.entries.map { it.wireName }
        assertFalse(ids.any { "rule-set" in it || "bypass" in it || "hwid" in it })
    }
}
