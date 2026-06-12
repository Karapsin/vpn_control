package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.shared.storageapi.LocationUpdateResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidLocationActionsServiceTest {
    @Test
    fun saveLocationShowsBlockedDialogForSubscriptionEdit() {
        val rawLink = testProfile("Blocked").rawLink
        val statuses = mutableListOf<String>()
        val harness = harness(
            initialState = MainUiState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                currentLocations = listOf(rawLink),
                editingLocationIndex = 0,
                locationDraft = rawLink,
            ),
            updateStatus = { statuses += it },
        )

        harness.service.saveLocation()

        assertTrue(harness.state.showLocationMutationBlockedDialog)
        assertEquals(
            LocationStatusMessages.subscriptionLocationSaveReadOnly(),
            harness.state.locationMutationBlockedMessage,
        )
        assertEquals(emptyList<String>(), statuses)
    }

    @Test
    fun importLocationsReportsBlockedSubscriptionMode() {
        val statuses = mutableListOf<String>()
        val harness = harness(
            initialState = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION),
            updateStatus = { statuses += it },
        )

        harness.service.importLocations("not relevant")

        assertEquals(listOf(LocationStatusMessages.importLocationsBlocked()), statuses)
    }

    @Test
    fun deleteSelectedRunningLocationStopsConnection() {
        val rawLink = LocationConfigs.encodeStoredLocation(testProfile("Selected"))
        val statuses = mutableListOf<String>()
        var stopCalls = 0
        val harness = harness(
            initialState = MainUiState(
                appMode = AppMode.VPN,
                profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                currentLocations = listOf(rawLink),
                selectedProfileRawLink = rawLink,
                isVpnRunning = true,
            ),
            updateStatus = { statuses += it },
            updateCurrentLocations = { controller, next ->
                controller.update { it.copy(currentLocations = next) }
                LocationUpdateResult(selectedMissing = true)
            },
            stopConnection = { controller ->
                stopCalls += 1
                controller.update { it.copy(isVpnRunning = false) }
                Result.success(Unit)
            },
        )

        harness.service.deleteLocation(0)

        assertEquals(1, stopCalls)
        assertEquals(emptyList<String>(), harness.state.currentLocations)
        assertEquals(
            LocationStatusMessages.selectedLocationRemovedConnectionStopped(AppMode.VPN, "Selected"),
            statuses.single(),
        )
    }

    @Test
    fun selectLocationRestoresSnapshotWhenApplyFailsBeforePersistence() {
        val rawLink = LocationConfigs.encodeStoredLocation(testProfile("Candidate"))
        val previous = PersistedState(selectedProfileRawLink = "old")
        val statuses = mutableListOf<String>()
        var restored = false
        val harness = harness(
            initialState = MainUiState(
                profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                currentLocations = listOf(rawLink),
            ),
            updateStatus = { statuses += it },
            snapshot = { previous },
            restoreSnapshot = { controller, state ->
                restored = true
                controller.update { it.copy(selectedProfileRawLink = state.selectedProfileRawLink) }
            },
            selectionFromRawLink = { _, _ -> Result.success(profileSelection("Candidate")) },
            applyAndPersistSelection = { _, _ ->
                SelectionCommitResult(
                    stage = SelectionCommitStage.APPLY_FAILED,
                    error = IllegalStateException("apply failed"),
                )
            },
        )

        harness.service.selectLocation(0)

        assertTrue(restored)
        assertEquals("old", harness.state.selectedProfileRawLink)
        assertEquals("apply failed", statuses.single())
        assertFalse(harness.state.isBusy)
    }

    private data class Harness(
        val service: AndroidLocationActionsService,
        val controller: MainController,
    ) {
        val state: MainUiState
            get() = controller.currentState()
    }

    private fun harness(
        initialState: MainUiState,
        updateStatus: suspend (String) -> Unit = {},
        snapshot: suspend () -> PersistedState = { PersistedState() },
        restoreSnapshot: suspend (MainController, PersistedState) -> Unit = { _, _ -> },
        updateCurrentLocations: suspend (MainController, List<String>) -> LocationUpdateResult = { controller, next ->
            controller.update { it.copy(currentLocations = next) }
            LocationUpdateResult(selectedMissing = false)
        },
        selectionFromRawLink: suspend (String, String) -> Result<ProfileSelection> = { _, _ ->
            Result.failure(IllegalStateException("No selection"))
        },
        applyAndPersistSelection: suspend (ProfileSelection, String) -> SelectionCommitResult = { _, _ ->
            SelectionCommitResult(SelectionCommitStage.SUCCESS)
        },
        rollbackSelectionChange: suspend (PersistedState, String) -> String = { _, message -> message },
        stopConnection: suspend (MainController) -> Result<Unit> = { Result.success(Unit) },
        benchmarkLocation: suspend (String) -> Result<ProfileBenchmark> = {
            Result.failure(IllegalStateException("not configured"))
        },
    ): Harness {
        val controller = MainController(initialState)
        val service = AndroidLocationActionsService(
            controller = controller,
            stateProvider = controller::currentState,
            launch = { block -> runBlocking { block() } },
            launchTrackedBusyOperation = { block -> runBlocking { block() } },
            setBusy = { busy -> controller.update { it.copy(isBusy = busy) } },
            setRefreshing = { refreshing -> controller.update { it.copy(isRefreshing = refreshing) } },
            updateStatus = updateStatus,
            snapshot = snapshot,
            restoreSnapshot = { restoreSnapshot(controller, it) },
            updateCurrentLocations = { updateCurrentLocations(controller, it) },
            selectionFromRawLink = selectionFromRawLink,
            applyAndPersistSelection = applyAndPersistSelection,
            rollbackSelectionChange = rollbackSelectionChange,
            stopConnection = { stopConnection(controller) },
            benchmarkLocation = benchmarkLocation,
            appendLatencyHistory = {},
        )
        return Harness(service, controller)
    }

    private fun profileSelection(name: String): ProfileSelection {
        val profile = testProfile(name)
        return ProfileSelection(
            profile = profile,
            benchmark = ProfileBenchmark(
                profile = profile,
                primaryStatus = "ok",
                secondaryStatus = "ok",
                primaryTotal = 50.0,
                secondaryTotal = 60.0,
                score = 50.0,
                detail = "test=ok test_codes=200 tcp=50ms",
            ),
            runtimeConfigJson = "{}",
        )
    }

    private fun testProfile(name: String): ProxyProfile {
        return ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = name,
            server = "example.com",
            serverPort = 443,
            uuid = "11111111-1111-4111-8111-111111111111",
            network = "tcp",
            flow = "",
            security = "tls",
            sni = "example.com",
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none&type=tcp&security=tls&sni=example.com#$name",
        )
    }
}
