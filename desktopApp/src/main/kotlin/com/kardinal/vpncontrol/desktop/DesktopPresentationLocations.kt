package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow
import com.kardinal.vpncontrol.shared.ui.SavedLocationSelection

/** Renderable owner data; contains neither a stored profile nor a filesystem reference. */
internal data class DesktopPresentationLocation(
    val id: String?,
    val index: Int,
    val name: String,
    val server: String,
    val details: String,
    val benchmark: String,
    val legacyDetailsUnavailable: Boolean,
    val valid: Boolean,
    val selected: Boolean,
    val active: Boolean,
    val editable: Boolean,
) {
    fun toSharedRow() = SavedLocationRow(
        index = index - 1,
        rawLink = "", // Explicit selection makes legacy raw-profile matching unnecessary.
        name = name,
        server = server,
        details = details,
        benchmarkDetail = benchmark,
        autoSelectable = valid,
        isSelected = selected,
        selection = SavedLocationSelection(selected, active),
    )

    override fun toString() = "DesktopPresentationLocation(index=$index, data=<redacted>)"

    companion object {
        fun fromValues(value: ControlValue): List<DesktopPresentationLocation> {
            val rows = (value as ControlValue.ArrayValue).values
            return rows.mapIndexed { offset, row ->
                val fields = (row as ControlValue.ObjectValue).values
                require(fields.keys == setOf("id", "index", "name", "server", "details", "benchmark",
                    "legacyDetailsUnavailable", "valid", "selected", "active", "editable"))
                fun text(key: String) = (fields.getValue(key) as ControlValue.Text).value
                fun flag(key: String) = (fields.getValue(key) as ControlValue.BooleanValue).value
                val id = when (val raw = fields.getValue("id")) {
                    ControlValue.Null -> null
                    is ControlValue.Text -> raw.value.also { require(it.isNotBlank()) }
                    else -> error("INCOMPATIBLE_PROTOCOL")
                }
                val index = (fields.getValue("index") as ControlValue.IntegerValue).value
                require(index == offset.toLong() + 1)
                val active = flag("active")
                require(!active || id != null)
                DesktopPresentationLocation(id, index.toInt(), text("name"), text("server"),
                    text("details"), text("benchmark"), flag("legacyDetailsUnavailable"),
                    flag("valid"), flag("selected"), active, flag("editable"))
            }
        }
    }
}
