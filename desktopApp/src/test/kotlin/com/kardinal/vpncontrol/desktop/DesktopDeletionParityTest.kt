package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopDeletionParityTest {
    @Test
    fun deleteAndImportRestoreActiveRuntimeWhenPersistenceFails() = runTest {
        for (importing in listOf(false, true)) {
            for (rollbackFails in listOf(false, true)) {
                val records = listOf("socks://127.0.0.1:1080#Active").toDesktopLocationRecords(1)
                var state = MainUiState(isVpnRunning = true,
                    profileSourceMode = com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS,
                    selectedProfileRawLink = records.single().rawLink)
                var restores = 0
                val service = DesktopLocationService({ state }, { records }, { AppMode.PROXY_ONLY },
                    stopConnection = { state = state.copy(isVpnRunning = false); Result.success(Unit) },
                    commitState = { _, _ -> Result.failure(DesktopPersistenceException()) },
                    updateState = { state = it(state) },
                    captureRestore = {
                        assertTrue(state.isVpnRunning)
                        suspend {
                            restores++
                            if (rollbackFails) Result.failure(IllegalStateException("private error"))
                            else { state = state.copy(isVpnRunning = true); Result.success(Unit) }
                        }
                    })
                val result = if (importing) service.importRaw(com.kardinal.vpncontrol.data.LocationConfigs.export(
                    listOf("socks://127.0.0.2:1080#Replacement")).content) else service.deleteLocation(1)
                assertEquals(if (rollbackFails) "ROLLBACK_FAILED" else "PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
                assertEquals(1, restores)
                assertEquals(!rollbackFails, state.isVpnRunning)
                assertEquals(records.single().rawLink, state.selectedProfileRawLink)
            }
        }
    }

    @Test
    fun bulkImportRemovingOnlyPendingSelectionPreservesActiveRuntime() = runTest {
        var locations = listOf("socks://127.0.0.1:1080#Active", "socks://127.0.0.2:1080#Pending")
            .toDesktopLocationRecords(1)
        val active = locations.first()
        var state = MainUiState(isVpnRunning = true,
            profileSourceMode = com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS,
            selectedProfileRawLink = locations.last().rawLink)
        val service = DesktopLocationService({ state }, { locations }, { AppMode.VPN },
            stopConnection = { error("Import retained the active runtime") },
            commitState = { next, records -> state = next; locations = records; Result.success(Unit) },
            updateState = { state = it(state) },
            isActiveLocation = { it.rawLink == active.rawLink })
        val exported = com.kardinal.vpncontrol.data.LocationConfigs.export(listOf(active.rawLink))
        assertEquals(com.kardinal.vpncontrol.data.LocationConfigs.normalizeStoredReference(active.rawLink),
            com.kardinal.vpncontrol.data.LocationConfigs.normalizeStoredReference(
                com.kardinal.vpncontrol.data.LocationConfigs.import(exported.content).single()))
        assertTrue(service.importRaw(exported.content).isSuccess)
        assertTrue(state.isVpnRunning)
        assertEquals("", state.selectedProfileRawLink)
        assertEquals(1, locations.size)
    }

    @Test
    fun deletingPendingSelectionDoesNotStopDifferentActiveLocation() = runTest {
        var locations = listOf("socks://127.0.0.1:1080#Active", "socks://127.0.0.2:1080#Pending")
            .toDesktopLocationRecords(1)
        val active = locations[0]
        var state = MainUiState(isVpnRunning = true, selectedProfileRawLink = locations[1].rawLink)
        var stops = 0
        val service = DesktopLocationService({ state }, { locations }, { AppMode.VPN },
            stopConnection = { stops++; state = state.copy(isVpnRunning = false); Result.success(Unit) },
            commitState = { next, records -> state = next; locations = records; Result.success(Unit) },
            updateState = { state = it(state) },
            isActiveLocation = { it.rawLink == active.rawLink })
        assertTrue(service.deleteLocation(2).isSuccess)
        assertEquals(0, stops)
        assertTrue(state.isVpnRunning)
        assertEquals("", state.selectedProfileRawLink)
        assertTrue(service.deleteLocation(1).isSuccess)
        assertEquals(1, stops)
        assertFalse(state.isVpnRunning)
    }

    @Test
    fun failedPersistenceAndSubscriptionOwnedRecordsCannotReportDeletion() = runTest {
        val locations = listOf("socks://127.0.0.1:1080#Manual").toDesktopLocationRecords(1)
        val state = MainUiState(selectedProfileRawLink = locations.single().rawLink)
        var commits = 0
        var records = locations
        val service = DesktopLocationService({ state }, { records }, { null },
            stopConnection = { error("No runtime operation expected") },
            commitState = { _, _ -> commits++; Result.failure(DesktopPersistenceException()) },
            updateState = { error("Failed delete must not publish") })
        assertTrue(service.deleteLocation(1).exceptionOrNull() is DesktopPersistenceException)
        assertEquals(1, commits)
        records = locations.map { it.copy(sourceUrl = "https://example.test/sub") }
        assertEquals("READ_ONLY", service.deleteLocation(1).exceptionOrNull()?.message)
        assertEquals(1, commits)
    }
}
