package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.DiagnosticsSanitizer
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Owner-local cursor history, updated synchronously with each published log state. */
internal class DesktopLogCursorJournal(initial: List<ConnectionLogEntry>, private val capacity: Int = 200) {
    private data class Row(val sequence: Long, val sourceId: String, val entry: ConnectionLogEntry)
    private val prefix = "log-${UUID.randomUUID()}-"
    private var sequence = 0L
    private var rows = emptyList<Row>()
    private var observedEntries: List<ConnectionLogEntry>? = null
    init { require(capacity > 0); sync(initial) }

    @Synchronized fun entries(): List<ConnectionLogEntry> = rows.map { it.entry }

    @Synchronized fun sync(entries: List<ConnectionLogEntry>): List<ConnectionLogEntry> {
        if (observedEntries == entries) return this.entries()
        observedEntries = entries
        val previous = rows.associateBy { it.sourceId }
        rows = entries.map { entry ->
            // Live state carries our sequence IDs, so a rollback can restore an older
            // entry without turning it into a new event after it left the bounded ring.
            val owned = entry.id.takeIf { it.startsWith(prefix) }?.removePrefix(prefix)?.toLongOrNull()
                ?.takeIf { it in 1..sequence && cursor(it) == entry.id }
            val retained = previous[entry.id]?.takeIf { it.entry.message == entry.message &&
                it.entry.createdAtEpochMillis == entry.createdAtEpochMillis }?.sequence
            val id = owned ?: retained ?: next()
            Row(id, entry.id, entry.copy(id = cursor(id)))
        }.distinctBy { it.sequence }.sortedBy { it.sequence }.takeLast(capacity)
        return this.entries()
    }

    @Synchronized fun read(arguments: Map<String, ControlValue>): Result<Map<String, ControlValue>> = runCatching {
        require(arguments.keys.all { it == "limit" || it == "after" })
        val limit = if ("limit" in arguments) requireNotNull((arguments["limit"] as? ControlValue.Text)?.value
            ?.toIntOrNull()?.takeIf { it >= 0 }) else 100
        val after = if ("after" in arguments) {
            val cursor = requireNotNull((arguments["after"] as? ControlValue.Text)?.value)
            require(cursor.startsWith(prefix))
            val suffix = cursor.removePrefix(prefix)
            requireNotNull(suffix.toLongOrNull()?.takeIf { it >= 0 && it <= sequence && it.toString() == suffix })
        } else null
        val newer = if (after == null) rows else rows.filter { it.sequence > after }
        val gap = after != null && after < sequence && (newer.isEmpty() ||
            newer.first().sequence > after + 1 || newer.zipWithNext().any { (left, right) -> right.sequence > left.sequence + 1 })
        val selected = if (after == null) newer.takeLast(limit) else newer.take(limit)
        val next = selected.lastOrNull()?.sequence ?: if (after == null || newer.isEmpty()) sequence else after
        mapOf(
            "entries" to ControlValue.ArrayValue(selected.map { row -> ControlValue.ObjectValue(mapOf(
                "id" to ControlValue.Text(cursor(row.sequence)),
                "createdAtEpochMillis" to ControlValue.IntegerValue(row.entry.createdAtEpochMillis),
                "message" to ControlValue.Text(DiagnosticsSanitizer.redactText(row.entry.message)),
            )) }),
            "nextCursor" to ControlValue.Text(cursor(next)),
            "gap" to ControlValue.BooleanValue(gap),
        )
    }

    private fun next(): Long { check(sequence < Long.MAX_VALUE); return ++sequence }
    private fun cursor(value: Long) = prefix + value
}
