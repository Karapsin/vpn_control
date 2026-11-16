package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/** `logs` entries carry a typed status beside the redacted message, so a client can translate it. */
class ControlLogCursorJournalStatusTest {
    @Test
    fun typedEntryCarriesItsKeyAndRedactedArgumentsBesideTheMessage() {
        val notice = StatusMessages.encode(StatusMessageKey.SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED,
            "workspace.json.unreadable-20261116T101500Z-0badc0de")
        val entry = entries(notice).single()

        assertEquals(ControlValue.Text("SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED(workspace.json.unreadable-20261116T101500Z-0badc0de)"),
            entry["message"])
        assertEquals(ControlValue.ObjectValue(mapOf(
            "key" to ControlValue.Text("SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED"),
            "args" to ControlValue.ArrayValue(listOf(ControlValue.Text("workspace.json.unreadable-20261116T101500Z-0badc0de"))),
        )), entry["status"])
    }

    @Test
    fun argumentsAreRedactedLikeThePresentation() {
        val link = "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443#Private"
        val restoring = entries(StatusMessages.encode(StatusMessageKey.RESTORING_PREVIOUS_CONNECTION, link)).single()
        val restoringArgs = ((restoring["status"] as ControlValue.ObjectValue).values["args"] as ControlValue.ArrayValue).values
        assertEquals(listOf(ControlValue.Text("<vless-link-redacted>")), restoringArgs)

        val failed = entries(StatusMessages.encode(StatusMessageKey.CONNECTION_START_FAILED, "exception at /home/someone/x")).single()
        val failedArgs = ((failed["status"] as ControlValue.ObjectValue).values["args"] as ControlValue.ArrayValue).values
        assertEquals(listOf(ControlValue.Text("[redacted]")), failedArgs)
    }

    @Test
    fun plainEntryHasNoStatus() {
        val entry = entries("Disconnected").single()
        assertEquals(ControlValue.Text("Disconnected"), entry["message"])
        assertFalse("status" in entry)
    }

    private fun entries(message: String): List<Map<String, ControlValue>> {
        val journal = ControlLogCursorJournal(listOf(ConnectionLogEntry("source", message, 1L)), "log-test-")
        val read = journal.read(emptyMap()).getOrThrow()
        return (read.getValue("entries") as ControlValue.ArrayValue).values.map { (it as ControlValue.ObjectValue).values }
    }
}
