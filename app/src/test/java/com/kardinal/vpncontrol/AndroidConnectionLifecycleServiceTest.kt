package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidConnectionLifecycleServiceTest {
    @Test
    fun startAndPersistSelectionReportsPersistFailureAfterSuccessfulStart() = runBlocking {
        var state = MainUiState(appMode = AppMode.VPN)
        val statuses = mutableListOf<String>()
        var startCalls = 0
        val service = testService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            updateStatus = { statuses += it },
            startConnection = {
                startCalls += 1
                Result.success(Unit)
            },
            persistSelection = {
                error("persist failed")
            },
        )

        val result = service.startAndPersistSelection(
            selection = profileSelection(),
            statusMessage = "Starting test connection",
        )

        assertEquals(SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY, result.stage)
        assertEquals("persist failed", result.error?.message)
        assertEquals(1, startCalls)
        assertEquals(listOf("Starting test connection"), statuses)
        assertFalse(state.isStartingVpn)
    }

    @Test
    fun toggleConnectionStopsRunningConnection() = runBlocking {
        var state = MainUiState(appMode = AppMode.VPN, isVpnRunning = true)
        val statuses = mutableListOf<String>()
        var stopCalls = 0
        val service = testService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            updateStatus = { statuses += it },
            stopConnection = {
                stopCalls += 1
                state = state.copy(isVpnRunning = false)
                Result.success(Unit)
            },
        )

        service.toggleConnection()

        assertEquals(1, stopCalls)
        assertEquals(ConnectionStatusMessages.connectionStopped(AppMode.VPN), statuses.last())
        assertFalse(state.isBusy)
    }

    @Test
    fun toggleConnectionStartsAndPersistsPreparedSelection() = runBlocking {
        var state = MainUiState(appMode = AppMode.VPN, hasVpnPermission = true)
        val selection = profileSelection()
        val statuses = mutableListOf<String>()
        var startCalls = 0
        var persistCalls = 0
        val service = testService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            updateStatus = { statuses += it },
            ensureSelection = { Result.success(selection) },
            startConnection = {
                startCalls += 1
                state = state.copy(isVpnRunning = true)
                Result.success(Unit)
            },
            persistSelection = {
                persistCalls += 1
            },
        )

        service.toggleConnection()

        assertEquals(1, startCalls)
        assertEquals(1, persistCalls)
        assertEquals(ConnectionStatusMessages.connectionStarted(AppMode.VPN), statuses.last())
        assertFalse(state.isBusy)
        assertFalse(state.isStartingVpn)
    }

    @Test
    fun toggleConnectionWithoutVpnPermissionPostsPreconditionError() = runBlocking {
        var state = MainUiState(appMode = AppMode.VPN, hasVpnPermission = false)
        val statuses = mutableListOf<String>()
        var startCalls = 0
        val service = testService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            updateStatus = { statuses += it },
            startConnection = {
                startCalls += 1
                Result.success(Unit)
            },
        )

        service.toggleConnection()

        assertEquals(0, startCalls)
        assertEquals(BenchmarkStatusMessages.vpnPermissionRequired(), statuses.single())
        assertFalse(state.isBusy)
    }

    @Test
    fun toggleConnectionReportsStopFailure() = runBlocking {
        var state = MainUiState(appMode = AppMode.VPN, isVpnRunning = true)
        val statuses = mutableListOf<String>()
        val service = testService(
            stateProvider = { state },
            updateState = { transform -> state = transform(state) },
            updateStatus = { statuses += it },
            stopConnection = {
                Result.failure(IllegalStateException("stop failed"))
            },
        )

        service.toggleConnection()

        assertEquals("stop failed", statuses.last())
        assertTrue(state.isVpnRunning)
        assertFalse(state.isBusy)
    }
}

private fun testService(
    stateProvider: () -> MainUiState,
    updateState: ((MainUiState) -> MainUiState) -> Unit,
    updateStatus: suspend (String) -> Unit = {},
    snapshot: suspend () -> PersistedState = { PersistedState() },
    restoreSnapshot: suspend (PersistedState, Boolean) -> Unit = { _, _ -> },
    ensureSelection: suspend () -> Result<ProfileSelection> = {
        Result.failure(IllegalStateException("No selection"))
    },
    persistSelection: suspend (ProfileSelection) -> Unit = {},
    rehydrateSelection: suspend (PersistedState) -> Result<ProfileSelection> = {
        Result.failure(IllegalStateException("No saved selection"))
    },
    startConnection: suspend (ProfileSelection) -> Result<Unit> = { Result.success(Unit) },
    stopConnection: suspend () -> Result<Unit> = { Result.success(Unit) },
): AndroidConnectionLifecycleService {
    return AndroidConnectionLifecycleService(
        stateProvider = stateProvider,
        updateState = updateState,
        setBusy = { busy -> updateState { it.copy(isBusy = busy) } },
        updateStatus = updateStatus,
        snapshot = snapshot,
        restoreSnapshot = restoreSnapshot,
        ensureSelection = ensureSelection,
        persistSelection = persistSelection,
        rehydrateSelection = rehydrateSelection,
        startConnection = startConnection,
        stopConnection = stopConnection,
    )
}

private fun profileSelection(): ProfileSelection {
    val profile = ProxyProfile(
        protocol = ProxyProtocol.VLESS,
        remarks = "Test",
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
