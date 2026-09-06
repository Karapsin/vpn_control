package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import com.kardinal.vpncontrol.shared.ui.SavedLocationSelection

class DesktopLocationRowSelectionTest {
    @Test
    fun mapsOpaqueSelectedAndActiveIdentitiesIndependentlyOfLegacyFlag() {
        val row = listOf("socks://127.0.0.1:1080#Fixture").toDesktopLocationRecords(1).single()
        assertEquals(SavedLocationSelection(true, false), row.toSharedRow("pending", "pending", "active").selection)
        assertEquals(SavedLocationSelection(false, true), row.copy(isSelected = true)
            .toSharedRow("active", "pending", "active").selection)
        assertEquals(SavedLocationSelection(false, false), row.copy(isSelected = true)
            .toSharedRow(null, null, null).selection)
    }
}
