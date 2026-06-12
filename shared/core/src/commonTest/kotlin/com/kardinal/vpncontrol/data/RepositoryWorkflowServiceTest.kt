package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.delay
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

    @Test
    fun refreshAllSubscriptionsCachesUsesConfiguredConcurrency() = runTest {
        val subscriptions = listOf(
            SubscriptionSource(id = "sub-1", url = "one"),
            SubscriptionSource(id = "sub-2", url = "two"),
            SubscriptionSource(id = "sub-3", url = "three"),
        )
        var running = 0
        var maxRunning = 0

        val result = RepositoryWorkflowService.refreshAllSubscriptionsCaches(
            state = PersistedState(
                subscriptions = subscriptions,
                validationSettings = BenchmarkValidationSettings(subscriptionRefreshConcurrency = 2),
            ),
            fetchSubscriptionLocations = { sourceUrl ->
                running += 1
                maxRunning = maxOf(maxRunning, running)
                delay(10)
                running -= 1
                listOf(proxyProfile(rawLink = "socks://127.0.0.1:1080#$sourceUrl"))
            },
            updateSubscriptionCache = { _, _ -> },
            updateRefreshStatus = { _, _ -> },
            displayLabel = { it.url },
        ).getOrThrow()

        assertEquals(3, result.refreshedCount)
        assertEquals(2, maxRunning)
    }

    @Test
    fun selectionSummaryReplacesRepeatedBestSourceSuffixesWithCurrentSource() {
        val first = SubscriptionSource(id = "sub-1", url = "https://example.com/one", customName = "One")
        val second = SubscriptionSource(id = "sub-2", url = "https://example.com/two", customName = "Two")

        val summary = RepositoryWorkflowService.selectionSummary(
            state = PersistedState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                profileUrl = first.url,
                activeSubscriptionId = first.id,
                subscriptions = listOf(first, second),
            ),
            detail = "test=ok tcp=30.9ms • Best from: One • Best from: One",
            sourceUrl = second.url,
            sourceLabelForUrl = { url -> listOf(first, second).firstOrNull { it.url == url }?.customName },
        )

        assertEquals("test=ok tcp=30.9ms • Best from: Two", summary)
    }

    @Test
    fun selectionSummaryRemovesStaleBestSourceWhenSourceShouldNotBeShown() {
        val subscription = SubscriptionSource(id = "sub-1", url = "https://example.com/sub", customName = "Sub")

        val summary = RepositoryWorkflowService.selectionSummary(
            state = PersistedState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                profileUrl = subscription.url,
                activeSubscriptionId = subscription.id,
                subscriptions = listOf(subscription),
            ),
            detail = "test=ok tcp=30.9ms • Best from: Sub",
            sourceUrl = subscription.url,
            sourceLabelForUrl = { subscription.customName },
        )

        assertEquals("test=ok tcp=30.9ms", summary)
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
