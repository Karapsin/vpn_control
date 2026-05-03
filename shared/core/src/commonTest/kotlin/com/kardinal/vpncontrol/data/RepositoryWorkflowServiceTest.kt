package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class RepositoryWorkflowServiceTest {
    @Test
    fun refreshSubscriptionCacheUsesRequestedSubscriptionOnly() = runTest {
        val first = SubscriptionSource(id = "sub-1", url = "https://example.com/one")
        val second = SubscriptionSource(id = "sub-2", url = "https://example.com/two")
        val fetchedUrls = mutableListOf<String>()
        val updatedSubscriptions = mutableListOf<String>()

        val result = RepositoryWorkflowService.refreshSubscriptionCache(
            state = PersistedState(subscriptions = listOf(first, second)),
            subscriptionId = second.id,
            fetchSubscriptionLocations = { sourceUrl ->
                fetchedUrls += sourceUrl
                listOf(proxyProfile(rawLink = "socks://127.0.0.1:1080#Two"))
            },
            updateSubscriptionCache = { subscriptionId, rawLinks ->
                updatedSubscriptions += "$subscriptionId:${rawLinks.single()}"
            },
            updateRefreshStatus = { _, _ -> },
        ).getOrThrow()

        assertEquals(1, result.refreshedCount)
        assertEquals(listOf(second.url), fetchedUrls)
        assertEquals(listOf("${second.id}:socks://127.0.0.1:1080#Two"), updatedSubscriptions)
    }
}

private fun proxyProfile(rawLink: String): ProxyProfile = ProxyProfile(
    remarks = "Two",
    server = "127.0.0.1",
    serverPort = 1080,
    network = "",
    flow = "",
    security = "",
    sni = "",
    fingerprint = "",
    publicKey = "",
    shortId = "",
    path = "",
    hostHeader = "",
    serviceName = "",
    headerType = "",
    rawLink = rawLink,
)
