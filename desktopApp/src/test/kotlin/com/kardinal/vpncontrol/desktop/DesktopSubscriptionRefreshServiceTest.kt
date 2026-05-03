package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopSubscriptionRefreshServiceTest {
    @Test
    fun refreshActiveWithoutTargetsPostsNoRemoteSourceMessage() = runTest {
        var state = MainUiState()
        val service = service(
            stateProvider = { state },
            locationsProvider = { emptyList() },
            updateState = { transform -> state = transform(state) },
        )

        service.refreshActive()

        assertEquals(SubscriptionRefreshResultLogic.NO_REMOTE_SOURCE_MESSAGE, state.statusMessage)
        assertFalse(state.isBusy)
    }

    @Test
    fun autoRefreshTriggersPostRefreshSelectionWhenConnectionWasRunning() = runTest {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/subscription.txt",
            customName = "Example",
        )
        var state = MainUiState(
            profileUrl = subscription.url,
            activeSubscriptionId = subscription.id,
            subscriptions = listOf(subscription),
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            appMode = AppMode.VPN,
            isVpnRunning = true,
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
            findBestAfterSubscriptionRefresh = true,
            subscriptionRefreshCustomHours = 0.5,
        )
        var locations = emptyList<DesktopLocationRecord>()
        var postRefreshSelections = 0
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            fetcher = RefreshSubscriptionFetcher(
                mapOf(subscription.url to "socks://user:pass@127.0.0.1:1080#Auto%20Refresh"),
            ),
            isRuntimeRunning = { true },
            findBestAfterRefresh = { postRefreshSelections += 1 },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.runAutoRefreshCycle()

        assertEquals(1, postRefreshSelections)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
        assertEquals(1, state.subscriptions.single().cachedLocations.size)
        assertEquals(1, locations.size)
        assertEquals(SubscriptionStatusMessages.subscriptionRefreshed(), state.statusMessage)
    }

    @Test
    fun refreshSubscriptionOnlyRefreshesRequestedSubscription() = runTest {
        val first = SubscriptionSource(
            id = "sub-1",
            url = "https://example.com/one.txt",
            customName = "One",
        )
        val second = SubscriptionSource(
            id = "sub-2",
            url = "https://example.com/two.txt",
            customName = "Two",
        )
        var state = MainUiState(
            activeSubscriptionId = first.id,
            subscriptions = listOf(first, second),
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
        )
        var locations = emptyList<DesktopLocationRecord>()
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            fetcher = RefreshSubscriptionFetcher(
                mapOf(second.url to "socks://user:pass@127.0.0.1:1080#Second"),
            ),
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.refreshSubscription(second.id)

        assertEquals(emptyList(), state.subscriptions.first { it.id == first.id }.cachedLocations)
        assertEquals(1, state.subscriptions.first { it.id == second.id }.cachedLocations.size)
        assertEquals(1, locations.size)
        assertEquals(SubscriptionStatusMessages.subscriptionRefreshed(), state.statusMessage)
        assertFalse(state.isBusy)
    }

    @Test
    fun refreshStopsRunningConnectionWhenSelectedLocationWasRemoved() = runTest {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/subscription.txt",
            customName = "Example",
            cachedLocations = listOf("old-location"),
        )
        var state = MainUiState(
            profileUrl = subscription.url,
            activeSubscriptionId = subscription.id,
            subscriptions = listOf(subscription),
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            appMode = AppMode.VPN,
            isVpnRunning = true,
            selectedProfileName = "Old",
            selectedProfileServer = "192.0.2.1",
            selectedProfileRawLink = "old-location",
            selectedProfileSourceUrl = subscription.url,
        )
        var locations = listOf(
            DesktopLocationRecord(
                index = 0,
                sourceUrl = subscription.url,
                rawLink = "old-location",
                name = "Old",
                server = "192.0.2.1",
                details = "SOCKS",
                benchmarkDetail = "Imported",
                isValid = true,
                isSelected = true,
            ),
        )
        var stopMessage = ""
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            fetcher = RefreshSubscriptionFetcher(
                mapOf(subscription.url to "socks://user:pass@127.0.0.1:1080#New"),
            ),
            stopConnection = { message ->
                stopMessage = message.orEmpty()
                state = state.copy(isVpnRunning = false)
                Result.success(Unit)
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
            updateState = { transform -> state = transform(state) },
        )

        service.refresh(
            subscriptionsToRefresh = listOf(subscription),
            statusPrefix = "Refreshing",
        )

        assertEquals(SubscriptionStatusMessages.subscriptionRefreshRemovedSelectedStopped(AppMode.VPN), stopMessage)
        assertFalse(state.isVpnRunning)
        assertEquals("", state.selectedProfileRawLink)
        assertEquals(1, locations.size)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        locationsProvider: () -> List<DesktopLocationRecord>,
        fetcher: SubscriptionContentFetcher = RefreshSubscriptionFetcher(emptyMap()),
        isRuntimeRunning: () -> Boolean = { false },
        stopConnection: suspend (String?) -> Result<Unit> = { Result.success(Unit) },
        findBestAfterRefresh: suspend () -> Unit = {},
        commitState: (MainUiState, List<DesktopLocationRecord>) -> Unit = { _, _ -> },
        updateState: ((MainUiState) -> MainUiState) -> Unit,
    ): DesktopSubscriptionRefreshService {
        return DesktopSubscriptionRefreshService(
            stateProvider = stateProvider,
            locationsProvider = locationsProvider,
            subscriptionService = DesktopSubscriptionService(
                subscriptionContentFetcher = fetcher,
                clockMillis = { 1_000L },
                hwidGenerator = { "0123456789abcdef0123456789abcdef" },
            ),
            isRuntimeRunning = isRuntimeRunning,
            stopConnection = stopConnection,
            findBestAfterRefresh = findBestAfterRefresh,
            commitState = commitState,
            updateState = updateState,
        )
    }
}

private class RefreshSubscriptionFetcher(
    private val payloadsByUrl: Map<String, String>,
) : SubscriptionContentFetcher {
    override suspend fun fetch(url: String, subscriptionHwid: String): FetchedSubscriptionContent {
        return FetchedSubscriptionContent(
            body = payloadsByUrl[url] ?: error("Unexpected subscription fetch: $url"),
            contentType = "text/plain",
        )
    }
}
