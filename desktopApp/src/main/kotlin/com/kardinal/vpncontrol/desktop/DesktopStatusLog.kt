package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.PersistedState

private const val MAX_DESKTOP_CONNECTION_LOG_ITEMS = 200

internal fun MainUiState.withStatus(message: String): MainUiState = copy(
    statusMessage = message,
    connectionLog = connectionLog.withStatusEntry(message),
)

/** The same status line and log entry for a workspace that is persisted before any service exists. */
internal fun PersistedState.withStatus(message: String): PersistedState = copy(
    statusMessage = message,
    connectionLog = connectionLog.withStatusEntry(message),
)

private fun List<ConnectionLogEntry>.withStatusEntry(message: String): List<ConnectionLogEntry> =
    (this + ConnectionLogEntry(
        id = java.util.UUID.randomUUID().toString(),
        message = message,
        createdAtEpochMillis = System.currentTimeMillis(),
    )).takeLast(MAX_DESKTOP_CONNECTION_LOG_ITEMS)
