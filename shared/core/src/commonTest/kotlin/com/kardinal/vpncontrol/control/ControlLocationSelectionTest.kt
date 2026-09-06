package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ControlLocationSelectionTest {
    private data class Location(val storageIndex: Int, val name: String)
    private val visible = listOf(Location(17, "Office"), Location(30, "1"), Location(9, "東京"))

    @Test
    fun exactNumericNamePrecedesVisibleIndex() {
        assertEquals(visible[1], found("1"))
    }

    @Test
    fun positionIsOneBasedVisibleOrderNotStorageId() {
        assertEquals(visible[2], found("3"))
        assertEquals(visible[2], found("東京"))
        assertEquals(ControlCode.NOT_FOUND, rejected("17"))
    }

    @Test
    fun ambiguousNumericNameDoesNotFallBackToIndex() {
        val result = ControlLocationSelection.resolve("1", visible + Location(50, "1"), Location::name)
        assertEquals(ControlCode.AMBIGUOUS_LOCATION, assertIs<ControlLocationResolution.Rejected>(result).code)
    }

    @Test
    fun invalidAndOutOfRangeIndicesDoNotSelectAnything() {
        for (target in listOf("", "0", "-1", "+1", "2147483648", " 3 ", "1.0", "office")) {
            assertEquals(ControlCode.NOT_FOUND, rejected(target))
        }
    }

    private fun found(target: String) = assertIs<ControlLocationResolution.Found<Location>>(
        ControlLocationSelection.resolve(target, visible, Location::name)).location
    private fun rejected(target: String) = assertIs<ControlLocationResolution.Rejected>(
        ControlLocationSelection.resolve(target, visible, Location::name)).code
}
