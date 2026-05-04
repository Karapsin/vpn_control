package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest

class DesktopSubscriptionServiceTest {
    @Test
    fun refreshSubscriptionsGeneratesHwidAndRebuildsCachedLocations() = runTest {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/subscription.txt",
            customName = "Example",
        )
        val savedRaw = "socks://user:pass@127.0.0.1:1080#Saved"
        val refreshedRaw = "socks://user:pass@127.0.0.2:1080#Refreshed"
        val fetcher = CapturingSubscriptionFetcher(mapOf(subscription.url to refreshedRaw))
        val progress = mutableListOf<String>()
        val service = DesktopSubscriptionService(
            subscriptionContentFetcher = fetcher,
            clockMillis = { 1234L },
            hwidGenerator = { "0123456789abcdef0123456789abcdef" },
        )

        val payload = service.refreshSubscriptions(
            state = MainUiState(subscriptions = listOf(subscription)),
            locations = listOf(
                desktopLocation(index = 0, sourceUrl = "", rawLink = savedRaw),
            ),
            subscriptionsToRefresh = listOf(subscription),
            onProgress = progress::add,
        ).getOrThrow()

        assertEquals(listOf(SubscriptionStatusMessages.refreshingSubscriptionNamed("Example")), progress)
        assertEquals(listOf("0123456789abcdef0123456789abcdef"), fetcher.subscriptionHwids)
        assertEquals("0123456789abcdef0123456789abcdef", payload.subscriptionHwid)
        assertEquals(1, payload.refreshedCount)
        assertEquals(SubscriptionStatusMessages.subscriptionRefreshed(), payload.statusMessage)
        assertEquals(2, payload.locations.size)
        assertEquals(savedRaw, payload.locations.single { it.sourceUrl.isBlank() }.rawLink)
        val refreshedLocation = payload.locations.single { it.sourceUrl == subscription.url }
        assertEquals("Refreshed", refreshedLocation.name)
        assertEquals("127.0.0.2", refreshedLocation.server)
        assertTrue(refreshedLocation.rawLink.contains(refreshedRaw))
        assertEquals(1234L, payload.subscriptions.single().lastRefreshedAtEpochMillis)
        assertEquals(SubscriptionStatusMessages.locationsRefreshed(1), payload.subscriptions.single().lastRefreshStatus)
        assertEquals(1, payload.subscriptions.single().cachedLocations.size)
    }

    @Test
    fun refreshSubscriptionsKeepsExistingLocationsWhenFetchFails() = runTest {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/subscription.txt",
            customName = "Example",
        )
        val existingRaw = "socks://user:pass@127.0.0.2:1080#Existing"
        val service = DesktopSubscriptionService(
            subscriptionContentFetcher = CapturingSubscriptionFetcher(emptyMap()),
            clockMillis = { 5678L },
            hwidGenerator = { "0123456789abcdef0123456789abcdef" },
        )

        val payload = service.refreshSubscriptions(
            state = MainUiState(subscriptions = listOf(subscription)),
            locations = listOf(
                desktopLocation(index = 4, sourceUrl = subscription.url, rawLink = existingRaw),
            ),
            subscriptionsToRefresh = listOf(subscription),
            onProgress = {},
        ).getOrThrow()

        assertEquals(0, payload.refreshedCount)
        assertEquals(listOf(existingRaw), payload.locations.map(DesktopLocationRecord::rawLink))
        assertEquals(5678L, payload.subscriptions.single().lastRefreshedAtEpochMillis)
        assertTrue(payload.subscriptions.single().lastRefreshStatus.contains("Unexpected subscription fetch"))
        assertTrue(payload.statusMessage.contains("Example"))
    }

    @Test
    fun refreshSubscriptionsHonorsConcurrencyLimit() = runTest {
        val subscriptions = listOf(
            SubscriptionSource(id = "sub-1", url = "https://example.com/one.txt"),
            SubscriptionSource(id = "sub-2", url = "https://example.com/two.txt"),
            SubscriptionSource(id = "sub-3", url = "https://example.com/three.txt"),
        )
        var running = 0
        var maxRunning = 0
        val service = DesktopSubscriptionService(
            subscriptionContentFetcher = object : SubscriptionContentFetcher {
                override suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent {
                    running += 1
                    maxRunning = maxOf(maxRunning, running)
                    delay(10)
                    running -= 1
                    return FetchedSubscriptionContent(
                        body = "socks://user:pass@127.0.0.1:1080#${url.substringAfterLast('/')}",
                        contentType = "text/plain",
                    )
                }
            },
            hwidGenerator = { "0123456789abcdef0123456789abcdef" },
        )

        val payload = service.refreshSubscriptions(
            state = MainUiState(subscriptions = subscriptions),
            locations = emptyList(),
            subscriptionsToRefresh = subscriptions,
            onProgress = {},
            concurrency = 2,
        ).getOrThrow()

        assertEquals(3, payload.refreshedCount)
        assertEquals(2, maxRunning)
        assertEquals(subscriptions.map(SubscriptionSource::url), payload.locations.map(DesktopLocationRecord::sourceUrl).distinct())
    }

    @Test
    fun refreshStatusHelperUsesTypedMessages() {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/subscription.txt",
            customName = "Example",
        )

        assertEquals(
            SubscriptionStatusMessages.refreshingSubscriptionNamed("Example"),
            DesktopSubscriptionRefreshStatus.progress(subscription),
        )
        assertEquals(
            SubscriptionStatusMessages.locationsRefreshed(2),
            DesktopSubscriptionRefreshStatus.successfulLocationRefresh(2),
        )
        assertEquals(
            SubscriptionStatusMessages.failedToRefresh("Example"),
            DesktopSubscriptionRefreshStatus.failedSubscriptionRefresh(subscription, IllegalStateException()),
        )
        assertEquals(
            SubscriptionStatusMessages.subscriptionsRefreshed(),
            DesktopSubscriptionRefreshStatus.summary(
                refreshedCount = 1,
                failedSubscriptionNames = emptyList(),
                totalCount = 2,
            ),
        )
        assertEquals(
            SubscriptionStatusMessages.noSubscriptionsToRefresh(),
            assertFailsWith<IllegalStateException> {
                throw DesktopSubscriptionRefreshStatus.noSubscriptionsToRefresh()
            }.message,
        )
    }
}

private fun desktopLocation(
    index: Int,
    sourceUrl: String,
    rawLink: String,
): DesktopLocationRecord {
    return DesktopLocationRecord(
        index = index,
        sourceUrl = sourceUrl,
        rawLink = rawLink,
        name = "Location",
        server = "127.0.0.1",
        details = "SOCKS",
        benchmarkDetail = "Imported - not checked yet",
        isValid = true,
    )
}

private class CapturingSubscriptionFetcher(
    private val payloadsByUrl: Map<String, String>,
) : SubscriptionContentFetcher {
    val subscriptionHwids = mutableListOf<String>()

    override suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent {
        subscriptionHwids += subscriptionHwid
        return FetchedSubscriptionContent(
            body = payloadsByUrl[url] ?: error("Unexpected subscription fetch: $url"),
            contentType = "text/plain",
        )
    }
}
