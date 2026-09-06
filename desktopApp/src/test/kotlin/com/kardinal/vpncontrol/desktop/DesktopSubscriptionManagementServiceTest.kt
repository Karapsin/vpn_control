package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
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
            profileTitleDraft = "VLESS (auto)",
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
        assertEquals("VLESS (auto)", state.subscriptions.single().customName)
        assertFalse(state.showAddSubscriptionEditor)
        assertEquals(SubscriptionStatusMessages.subscriptionSaved(), state.statusMessage)
    }

    @Test
    fun saveSubscriptionRenameCanChangeSourceAndClearsOldLocations() {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/old.txt",
            customName = "Old",
            cachedLocations = listOf("raw"),
        )
        var state = MainUiState(
            activeSubscriptionId = subscription.id,
            profileUrl = subscription.url,
            subscriptions = listOf(subscription),
            profileHistoryRenameSource = subscription.url,
            profileHistoryRenameUrlDraft = "https://example.com/new.txt",
            profileHistoryRenameDraft = "New",
            showProfileHistoryRenameDialog = true,
        )
        var locations = listOf(
            DesktopLocationRecord(
                index = 0,
                sourceUrl = subscription.url,
                rawLink = "raw",
                name = "Old",
                server = "127.0.0.1",
                details = "SOCKS",
                benchmarkDetail = "not checked",
                isValid = true,
            ),
        )
        val service = service(
            stateProvider = { state },
            locationsProvider = { locations },
            commitState = { nextState, nextLocations ->
                state = nextState
                locations = nextLocations
            },
        )

        service.saveSubscriptionRename()

        assertEquals("https://example.com/new.txt", state.profileUrl)
        assertEquals("https://example.com/new.txt", state.subscriptions.single().url)
        assertEquals("New", state.subscriptions.single().customName)
        assertEquals(emptyList(), state.subscriptions.single().cachedLocations)
        assertTrue(locations.isEmpty())
        assertFalse(state.showProfileHistoryRenameDialog)
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

        assertEquals(SubscriptionStatusMessages.subscriptionDeleteRemovedSelectedStopped(AppMode.VPN), stopMessage)
        assertFalse(state.isVpnRunning)
        assertTrue(state.subscriptions.isEmpty())
        assertTrue(locations.isEmpty())
        assertEquals("", state.selectedProfileRawLink)
        assertEquals(SubscriptionStatusMessages.subscriptionDeleted(), state.statusMessage)
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
            commitState = { state, locations -> commitState(state, locations); Result.success(Unit) },
            updateState = { transform ->
                commitState(transform(stateProvider()), locationsProvider())
            },
            idGenerator = { "generated-id" },
        )
    }
}
