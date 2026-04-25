package com.kardinal.vpncontrol.shared.storageapi

import com.kardinal.vpncontrol.model.PersistedState

interface RefreshScheduler {
    suspend fun sync(state: PersistedState)

    suspend fun scheduleNext(state: PersistedState)

    fun cancel()
}
