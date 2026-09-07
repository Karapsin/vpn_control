package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlLogCursorJournal
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.ControlValue
import java.util.UUID

/** Desktop owns synchronization; cursor semantics are shared with Android. */
internal class DesktopLogCursorJournal(initial: List<ConnectionLogEntry>, capacity: Int = 200) {
    private val journal = ControlLogCursorJournal(initial, "log-${UUID.randomUUID()}-", capacity)
    @Synchronized fun entries(): List<ConnectionLogEntry> = journal.entries()
    @Synchronized fun sync(entries: List<ConnectionLogEntry>): List<ConnectionLogEntry> = journal.sync(entries)
    @Synchronized fun read(arguments: Map<String, ControlValue>): Result<Map<String, ControlValue>> = journal.read(arguments)
}
