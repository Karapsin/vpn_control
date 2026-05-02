package com.kardinal.vpncontrol.shared.storageapi

data class FetchedSubscriptionContent(
    val body: String,
    val contentType: String?,
    val headers: Map<String, String> = emptyMap(),
)

object SubscriptionRequestHeaders {
    const val HWID_HEADER = "x-hwid"

    fun build(
        userAgent: String,
        accept: String,
        subscriptionHwid: String,
    ): Map<String, String> {
        return buildMap {
            put("User-Agent", userAgent)
            put("Accept", accept)
            subscriptionHwid.trim().takeIf(String::isNotBlank)?.let { hwid ->
                put(HWID_HEADER, hwid)
            }
        }
    }
}

interface SubscriptionContentFetcher {
    suspend fun fetch(url: String): FetchedSubscriptionContent = fetch(url, subscriptionHwid = "")

    suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent
}
