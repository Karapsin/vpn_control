package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidFindBestActionsServiceTest {
    @Test
    fun refreshWithoutLocationsPostsPreconditionError() = runBlocking {
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        val statuses = mutableListOf<String>()
        var refreshCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfile = {
                refreshCalls += 1
                Result.success(profileSelection("Should not run"))
            },
        )

        service.refresh()

        assertEquals(0, refreshCalls)
        assertEquals(listOf(SubscriptionStatusMessages.addSavedLocationFirst()), statuses)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshSuccessStartsWinnerAndRecordsLatency() = runBlocking {
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
        )
        val statuses = mutableListOf<String>()
        val latencies = mutableListOf<LatencyHistoryEntry>()
        val selection = profileSelection("Germany")
        var startCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfile = { Result.success(selection) },
            startAndPersistSelection = { _, _ ->
                startCalls += 1
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
            appendLatencyHistory = { latencies += it },
        )

        service.refresh()

        assertEquals(1, startCalls)
        assertEquals(
            ConnectionStatusMessages.findBestStart(ProfileSourceMode.CURRENT_LOCATIONS),
            statuses.first(),
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
            statuses.last(),
        )
        assertEquals("fixed-id", latencies.single().id)
        assertEquals("Germany", latencies.single().profileName)
        assertEquals(1234L, latencies.single().createdAtEpochMillis)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshRestoresSnapshotWhenPersistFailsBeforeApply() = runBlocking {
        val previous = PersistedState(selectedProfileName = "Previous")
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
        )
        val statuses = mutableListOf<String>()
        var restored = false
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            snapshot = { previous },
            restoreSnapshot = {
                restored = true
                state = state.copy(selectedProfileName = it.selectedProfileName)
            },
            refreshBestProfile = { Result.success(profileSelection("Candidate")) },
            startAndPersistSelection = { _, _ ->
                SelectionCommitResult(
                    stage = SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY,
                    error = IllegalStateException("persist failed"),
                )
            },
        )

        service.refresh()

        assertTrue(restored)
        assertEquals("Previous", state.selectedProfileName)
        assertEquals("persist failed", statuses.last())
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshRetriesSearchBeforeSuccess() = runBlocking {
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
            validationSettings = BenchmarkValidationSettings(retryCount = 1),
        )
        val statuses = mutableListOf<String>()
        var refreshCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfile = {
                refreshCalls += 1
                if (refreshCalls == 1) {
                    Result.failure(IllegalStateException("first failed"))
                } else {
                    Result.success(profileSelection("Retry Winner"))
                }
            },
            startAndPersistSelection = { _, _ ->
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
        )

        service.refresh()

        assertEquals(2, refreshCalls)
        assertTrue(
            statuses.any {
                it == BenchmarkStatusMessages.retryingBestLocationSearch(attempt = 2, total = 2)
            },
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Retry Winner"),
            statuses.last(),
        )
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        setBusy: (Boolean) -> Unit,
        setRefreshing: (Boolean) -> Unit,
        updateStatus: suspend (String) -> Unit = {},
        snapshot: suspend () -> PersistedState = { PersistedState() },
        restoreSnapshot: suspend (PersistedState) -> Unit = {},
        refreshBestProfile: suspend () -> Result<ProfileSelection> = {
            Result.success(profileSelection("Winner"))
        },
        startAndPersistSelection: suspend (ProfileSelection, String) -> SelectionCommitResult = { _, _ ->
            SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
        },
        rollbackSelectionChange: suspend (PersistedState, String) -> String = { _, message -> message },
        stopConnection: suspend () -> Result<Unit> = { Result.success(Unit) },
        appendLatencyHistory: suspend (LatencyHistoryEntry) -> Unit = {},
    ): AndroidFindBestActionsService {
        return AndroidFindBestActionsService(
            stateProvider = stateProvider,
            launchTrackedBusyOperation = { block -> runBlocking { block() } },
            setBusy = setBusy,
            setRefreshing = setRefreshing,
            updateStatus = updateStatus,
            snapshot = snapshot,
            restoreSnapshot = restoreSnapshot,
            refreshBestProfile = refreshBestProfile,
            startAndPersistSelection = startAndPersistSelection,
            rollbackSelectionChange = rollbackSelectionChange,
            stopConnection = stopConnection,
            appendLatencyHistory = appendLatencyHistory,
            idGenerator = { "fixed-id" },
            clockMillis = { 1234L },
        )
    }
}

private fun profileSelection(name: String): ProfileSelection {
    val profile = ProxyProfile(
        protocol = ProxyProtocol.VLESS,
        remarks = name,
        server = "test.example.net",
        serverPort = 443,
        uuid = "11111111-1111-4111-8111-111111111111",
        network = "tcp",
        flow = "",
        security = "tls",
        sni = "test.example.net",
        fingerprint = "",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "",
        rawLink = "vless://test",
    )
    return ProfileSelection(
        profile = profile,
        benchmark = ProfileBenchmark(
            profile = profile,
            primaryStatus = "ok",
            secondaryStatus = "ok",
            primaryTotal = 50.0,
            secondaryTotal = 60.0,
            score = 50.0,
            detail = "primary=ok secondary=ok tcp=50ms",
        ),
        runtimeConfigJson = "{}",
    )
}
