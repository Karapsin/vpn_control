package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ConnectionLogEntry

internal fun MainUiState.withStatus(message: String): MainUiState {
    val now = System.currentTimeMillis()
    return copy(
        statusMessage = message,
        connectionLog = (connectionLog + ConnectionLogEntry(
            id = "desktop-$now-${connectionLog.size}",
            message = message,
            createdAtEpochMillis = now,
        )).takeLast(50),
    )
}
