package com.kardinal.vpncontrol.shared.storageapi

interface RuntimeConfigStore {
    suspend fun readRuntimeConfig(): String?

    suspend fun writeRuntimeConfig(configJson: String)

    suspend fun clearRuntimeConfig()
}
