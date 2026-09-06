package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlValue
import kotlin.test.*

class DesktopPresentationLocationsTest {
    private fun fields() = mapOf(
        "id" to ControlValue.Text("opaque-target"), "index" to ControlValue.IntegerValue(1),
        "name" to ControlValue.Text("2"), "server" to ControlValue.Text("example.test"),
        "details" to ControlValue.Text("SOCKS"), "benchmark" to ControlValue.Text(""),
        "legacyDetailsUnavailable" to ControlValue.BooleanValue(false),
        "valid" to ControlValue.BooleanValue(true), "selected" to ControlValue.BooleanValue(false),
        "active" to ControlValue.BooleanValue(true), "editable" to ControlValue.BooleanValue(true),
    )

    private fun decode(fields: Map<String, ControlValue>) = DesktopPresentationLocation.fromValues(
        ControlValue.ArrayValue(listOf(ControlValue.ObjectValue(fields))))

    @Test fun renderingUsesExplicitOwnerSelectionWithoutPrivateProfileContent() {
        val location = decode(fields()).single()
        assertEquals("opaque-target", location.id)
        val row = location.toSharedRow()
        assertEquals(0, row.index)
        assertEquals("2", row.name)
        assertEquals("", row.rawLink)
        assertFalse(requireNotNull(row.selection).selected)
        assertTrue(requireNotNull(row.selection).active)
        assertFalse(location.toString().contains("example.test"))
        val pending = decode(fields() + mapOf("selected" to ControlValue.BooleanValue(true),
            "active" to ControlValue.BooleanValue(false))).single().toSharedRow()
        assertTrue(requireNotNull(pending.selection).selected)
        assertFalse(requireNotNull(pending.selection).active)
    }

    @Test fun malformedFieldsAndUnexpectedPrivatePayloadCannotBecomeRenderableRows() {
        for (invalid in listOf(
            fields() - "editable",
            fields() + ("rawLink" to ControlValue.Text("private-profile")),
            fields() + ("index" to ControlValue.IntegerValue(Long.MAX_VALUE)),
            fields() + ("index" to ControlValue.IntegerValue(0)),
            fields() + ("id" to ControlValue.Text(" ")),
            fields() + ("active" to ControlValue.Text("true")),
            fields() + ("id" to ControlValue.Null),
        )) assertFails { decode(invalid) }
        val unavailable = decode(fields() + mapOf("id" to ControlValue.Null,
            "active" to ControlValue.BooleanValue(false))).single()
        assertNull(unavailable.id)
    }
}
