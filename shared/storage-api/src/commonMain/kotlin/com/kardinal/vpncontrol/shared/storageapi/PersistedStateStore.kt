package com.kardinal.vpncontrol.shared.storageapi

import com.kardinal.vpncontrol.model.PersistedState
import kotlinx.coroutines.flow.Flow

interface PersistedStateStore {
    val state: Flow<PersistedState>

    suspend fun snapshot(): PersistedState
}
