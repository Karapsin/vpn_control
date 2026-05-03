package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopSubscriptionManagementServiceTest {
    @Test
    fun saveSubscriptionDraftCommitsNewSourceAndClosesEditor() {
        var state = MainUiState(
            profileDraft = "https://example.com/sub.txt",
            showAddSubscriptionEditor = true,
        )
        var locations = emptyList<DesktopLocationRecord>()
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
        )

        service.saveSubscriptionDraft()

        assertEquals("generated-id", state.activeSubscriptionId)
        assertEquals("https://example.com/sub.txt", state.profileUrl)
        assertEquals(listOf("https://example.com/sub.txt"), state.subscriptions.map(SubscriptionSource::url))
        assertFalse(state.showAddSubscriptionEditor)
        assertEquals(StatusMessages.subscriptionSaved(), state.statusMessage)
    }

    @Test
    fun deleteRunningSelectedSubscriptionStopsBeforeCommitAndKeepsStoppedState() = runTest {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/sub.txt",
        )
        var state = MainUiState(
            appMode = AppMode.VPN,
            isVpnRunning = true,
            subscriptions = listOf(subscription),
            activeSubscriptionId = subscription.id,
            profileUrl = subscription.url,
            selectedProfileName = "Selected",
            selectedProfileServer = "127.0.0.1",
            selectedProfileRawLink = "raw",
            selectedProfileSourceUrl = subscription.url,
        )
        var locations = listOf(
            DesktopLocationRecord(
                index = 0,
                sourceUrl = subscription.url,
                rawLink = "raw",
                name = "Selected",
                server = "127.0.0.1",
                details = "SOCKS",
                benchmarkDetail = "not checked",
                isValid = true,
            ),
        )
        var stopMessage = ""
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            stopConnection = { message ->
                stopMessage = message.orEmpty()
                state = state.copy(isVpnRunning = false)
                Result.success(Unit)
            },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
        )

        service.deleteSubscription(subscription.id)

        assertEquals(StatusMessages.subscriptionDeleteRemovedSelectedStopped(AppMode.VPN), stopMessage)
        assertFalse(state.isVpnRunning)
        assertTrue(state.subscriptions.isEmpty())
        assertTrue(locations.isEmpty())
        assertEquals("", state.selectedProfileRawLink)
        assertEquals(StatusMessages.subscriptionDeleted(), state.statusMessage)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        locationsProvider: () -> List<DesktopLocationRecord>,
        stopConnection: suspend (String?) -> Result<Unit> = { Result.success(Unit) },
        commitState: (MainUiState, List<DesktopLocationRecord>) -> Unit,
    ): DesktopSubscriptionManagementService {
        return DesktopSubscriptionManagementService(
            stateProvider = stateProvider,
            locationsProvider = locationsProvider,
            validateSubscriptionSource = { Result.success(Unit) },
            stopConnection = stopConnection,
            commitState = commitState,
            updateState = { transform ->
                commitState(transform(stateProvider()), locationsProvider())
            },
            idGenerator = { "generated-id" },
        )
    }
}
