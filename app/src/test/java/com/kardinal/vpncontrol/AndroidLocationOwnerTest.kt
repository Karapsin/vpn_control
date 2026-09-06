package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidLocationOwnerTest {
    @Test fun activeASelectionBAndRevertKeepRuntimeUnchangedWithExactRetryAndStaleGuards() = runTest {
        val a = "socks://127.0.0.1:1080#A"
        val b = "socks://127.0.0.1:1081#B"
        val rows = listOf(a, b).map(LocationConfigs::normalizeStoredReference)
        val observer = AndroidRuntimeObserver()
        var state = PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = rows, savedLocations = rows,
            selectedProfileRawLink = a, selectedProfileJson = rows[0], selectedProfileName = "A", runtimeConfigJson = "ACTIVE_CONFIG")
        observer.started(Any(), AppMode.VPN, "ACTIVE_CONFIG", ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), state)))
        val runtime = observer.state.value
        var committed = ControlCommitted("owner", 0, state)
        var writes = 0
        val control = AndroidSettingsControl("owner", backgroundScope, { committed },
            { _, _, _ -> error("settings path") }, {}, observer::pendingRestart,
            location = { operation, values, owner, revision ->
                check(owner == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                val plan = AndroidLocationControl.plan(committed.value, operation, values, owner, AppStrings(AppLanguage.ENGLISH))
                state = committed.value
                plan.selected?.let {
                    val profile = LocationConfigs.decodeStoredLocation(it)
                    state = state.copy(selectedProfileName = profile.remarks, selectedProfileRawLink = profile.rawLink,
                        selectedProfileJson = LocationConfigs.encodeStoredLocation(profile), selectedProfileSourceUrl = plan.source, runtimeConfigJson = "PREPARED_${profile.remarks}")
                }
                plan.locations?.let { state = state.copy(currentLocations = it, savedLocations = it) }
                if (state != committed.value) writes++
                committed = committed.copy(revision = committed.revision + if (state == committed.value) 0 else 1, value = state)
                AndroidSettingsCommit(committed, false, mapOf("id" to ControlValue.Text(plan.id)))
            })
        fun request(id: String, selector: String) = ControlRequest(id, ControlCommand(ControlOperationId.LOCATIONS_SELECT,
            mapOf("selector" to ControlValue.Text(AppStrings(AppLanguage.ENGLISH).locationLabel(ProfileSourceMode.CURRENT_LOCATIONS, selector)))), controllerId = "owner", ifRevision = committed.revision)
        val selectB = request("B", "B")
        val changed = control.execute(selectB)
        assertEquals(ControlCode.OK, changed.code); assertTrue(changed.restartRequired)
        assertEquals(runtime, observer.state.value)
        val visual = observer.locationVisualState(committed.value)
        val visibleRows = androidLocationRows(MainUiStateProjector.mergePersistedState(MainUiState(), committed.value), AppStrings(AppLanguage.ENGLISH), visual)
        assertEquals(true, visibleRows.first { it.rawLink == rows[0] }.selection?.active)
        assertEquals(false, visibleRows.first { it.rawLink == rows[0] }.selection?.selected)
        assertEquals(false, visibleRows.first { it.rawLink == rows[1] }.selection?.active)
        assertEquals(true, visibleRows.first { it.rawLink == rows[1] }.selection?.selected)
        assertEquals(changed, control.execute(selectB)); assertEquals(1, writes)
        val same = control.execute(request("sameB", "B"))
        assertEquals(1L, same.configurationRevision); assertTrue(same.restartRequired)
        assertEquals(ControlCode.CONFLICT, control.execute(selectB.copy(requestId = "stale")).code)
        val reverted = control.execute(request("A", "A"))
        assertFalse(reverted.restartRequired); assertEquals(runtime, observer.state.value)
        assertEquals(false, observer.locationVisualState(committed.value).restartRequired)
        val differentMode = committed.value.copy(appMode = AppMode.PROXY_ONLY)
        assertEquals(true, observer.locationVisualState(differentMode).restartRequired)
        assertEquals(2, writes)
        observer.resetCompleted(false)
        assertEquals(ControlCode.UNAVAILABLE, control.execute(request("unknown", "B")).code)
        assertEquals(2, writes)
    }
}
