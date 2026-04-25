package com.kardinal.vpncontrol.shared.storageapi

interface SearchStateStore : PersistedStateStore {
    suspend fun updateStatus(message: String)

    suspend fun updateCurrentLocations(rawLinks: List<String>): LocationUpdateResult

    suspend fun updateLocationBenchmarkDetails(details: Map<String, String>)

    suspend fun updateSubscriptionCache(
        subscriptionId: String,
        rawLinks: List<String>,
        refreshStatus: String = "",
    ): LocationUpdateResult

    suspend fun readLastSelectedProfile(): String?
}
