package com.kardinal.vpncontrol.shared.storageapi

data class FetchedSubscriptionContent(
    val body: String,
    val contentType: String?,
)

interface SubscriptionContentFetcher {
    suspend fun fetch(url: String): FetchedSubscriptionContent
}
