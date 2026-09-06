package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlin.test.*

class DesktopLogCursorJournalTest {
    private fun read(journal: DesktopLogCursorJournal, after: String? = null, limit: Int = 100) = journal.read(
        mapOf("limit" to ControlValue.Text(limit.toString())) + after?.let { mapOf("after" to ControlValue.Text(it)) }.orEmpty()).getOrThrow()
    private fun cursor(values: Map<String, ControlValue>) = (values.getValue("nextCursor") as ControlValue.Text).value
    private fun entries(values: Map<String, ControlValue>) = (values.getValue("entries") as ControlValue.ArrayValue).values

    @Test fun emptyAndZeroLimitHaveCursorsAndSameTimestampEntriesAreDistinct() {
        val journal = DesktopLogCursorJournal(emptyList())
        val initial = read(journal, limit = 0)
        val first = ConnectionLogEntry("first", "identical", 123)
        val second = ConnectionLogEntry("second", "identical", 123)
        journal.sync(listOf(first, second))
        val page = read(journal, cursor(initial), 1)
        assertEquals(1, entries(page).size)
        assertEquals(ControlValue.BooleanValue(false), page["gap"])
        val next = read(journal, cursor(page), 1)
        assertEquals(1, entries(next).size)
        assertNotEquals(cursor(page), cursor(next))
        assertTrue(entries(read(journal, cursor(next))).isEmpty())
        assertEquals(cursor(next), cursor(read(journal, limit = 0)))
    }

    @Test fun rolloverAndClearedHistoryAreExplicitGapsNotSilentLoss() {
        val journal = DesktopLogCursorJournal(emptyList(), capacity = 2)
        val emptyCursor = cursor(read(journal))
        val history = (1..3).map { ConnectionLogEntry("$it", "entry", 123) }
        journal.sync(history)
        val page = read(journal, emptyCursor)
        assertEquals(ControlValue.BooleanValue(true), page["gap"])
        assertEquals(2, entries(page).size)
        journal.sync(history) // No repeated additions from unchanged oversized input.
        assertEquals(cursor(page), cursor(read(journal)))
        journal.sync(emptyList())
        assertEquals(ControlValue.BooleanValue(true), read(journal, emptyCursor)["gap"])
        assertFalse(journal.read(mapOf("after" to ControlValue.Text("other-owner-0"))).isSuccess)
        assertFalse(journal.read(mapOf("after" to ControlValue.Null)).isSuccess)
    }

    @Test fun servicePublishesEveryCommittedEntryAndRedactsMessages() {
        val directory = Files.createTempDirectory("log-cursor-service")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            fun inspect(after: String? = null) = service.controlReadSnapshot(ControlCommand(ControlOperationId.LOGS,
                after?.let { mapOf("after" to ControlValue.Text(it)) }.orEmpty())).values.getOrThrow()
            val before = cursor(inspect())
            repeat(205) { service.postStatus("identical") }
            val page = inspect(before)
            assertEquals(ControlValue.BooleanValue(true), page["gap"])
            val first = entries(page)
            val secondPage = inspect(cursor(page))
            assertEquals(200, first.size + entries(secondPage).size)
            val ids = (first + entries(secondPage)).map { (it as ControlValue.ObjectValue).values["id"] }
            assertEquals(ids.size, ids.distinct().size)
            service.postStatus("https://example.test/private-token")
            val secret = inspect(cursor(secondPage))
            assertFalse(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(secret).contains("private-token"))
            assertEquals(0L, service.configurationRevision)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun fullRingAppendsHaveUniqueIdsEvenAtClockResolution() {
        var state = MainUiState()
        repeat(400) { state = state.withStatus("same") }
        assertEquals(200, state.connectionLog.size)
        assertEquals(200, state.connectionLog.map { it.id }.distinct().size)
    }

    @Test fun restoredOldHistoryIsNotReemittedAsNewLogEvents() {
        val journal = DesktopLogCursorJournal(emptyList(), capacity = 2)
        val original = journal.sync(listOf(ConnectionLogEntry("original", "before", 1)))
        val afterOriginal = cursor(read(journal))
        val changed = journal.sync(original + listOf(ConnectionLogEntry("next", "during", 2),
            ConnectionLogEntry("last", "during", 3)))
        val consumed = cursor(read(journal, afterOriginal))
        journal.sync(original) // Restore snapshot from before the later entries rolled out.
        assertTrue(entries(read(journal, consumed)).isEmpty())
        assertEquals(consumed, cursor(read(journal, consumed)))
        journal.sync(original + ConnectionLogEntry("new", "after", 4))
        assertEquals(1, entries(read(journal, consumed)).size)
        assertTrue(changed.none { it.id == original.single().id })
    }
}
