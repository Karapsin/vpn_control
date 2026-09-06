package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ConnectionLogEntry

private const val MAX_DESKTOP_CONNECTION_LOG_ITEMS = 200

internal fun MainUiState.withStatus(message: String): MainUiState {
    val now = System.currentTimeMillis()
    return copy(
        statusMessage = message,
        connectionLog = (connectionLog + ConnectionLogEntry(
            id = java.util.UUID.randomUUID().toString(),
            message = message,
            createdAtEpochMillis = now,
        )).takeLast(MAX_DESKTOP_CONNECTION_LOG_ITEMS),
    )
}
