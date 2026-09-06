package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidGuiLocationActionsTest {
    @Test fun oldRenderedSourceNeverRetargetsSameRawLocationAfterSubscriptionSwitch() = runBlocking {
        val raw = "socks://127.0.0.1:1080#Same"
        val rendered = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, activeSubscriptionId = "A", profileUrl = "https://a.invalid", currentLocations = listOf(raw))
        val target = androidRenderedLocationTarget(rendered, raw)
        val controller = MainController()
        controller.mutableState.value = rendered.copy(activeSubscriptionId = "B", profileUrl = "https://b.invalid")
        val committed = ControlCommitted("owner", 2, PersistedState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = "B", profileUrl = "https://b.invalid", currentLocations = listOf(raw)))
        val work = mutableListOf<suspend () -> Unit>(); var requests = 0
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add, { committed }, { request ->
            requests++; ControlResult("owner", request.requestId, ControlCode.OK, 2)
        })
        frontend.select(target); work.removeAt(0)()
        frontend.openTarget(target); work.removeAt(0)()
        frontend.delete(target); work.removeAt(0)()
        assertEquals(0, requests); assertFalse(controller.state.value.showLocationDialog)
        assertEquals("CONFLICT", controller.state.value.locationMutationBlockedMessage)
        assertEquals("AndroidRenderedLocationTarget(<redacted>)", target.toString())
    }
    @Test fun deletionUsesCapturedRawRowRatherThanLatestStorageIndex() = runBlocking {
        val a = "socks://127.0.0.1:1080#A"; val b = "socks://127.0.0.1:1081#B"
        val controller = MainController()
        controller.mutableState.value = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(a, b))
        var committed = ControlCommitted("owner", 1, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(a, b)))
        val work = mutableListOf<suspend () -> Unit>(); val requests = mutableListOf<ControlRequest>()
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add, { committed }, { request ->
            requests += request; ControlResult("owner", request.requestId, ControlCode.OK, committed.revision)
        })
        frontend.delete(a)
        committed = committed.copy(revision = 2, value = committed.value.copy(currentLocations = listOf(b, a)))
        work.removeAt(0)()
        assertEquals(ControlOperationId.LOCATIONS_DELETE, requests.single().command.operation)
        assertEquals(ControlValue.Text(com.kardinal.vpncontrol.data.AndroidLocationControl.identity("owner", committed.value, a)), requests.single().command.arguments["id"])
        frontend.delete(a); committed = committed.copy(value = committed.value.copy(currentLocations = listOf(b)))
        work.removeAt(0)(); assertEquals(1, requests.size)
        assertEquals("CONFLICT", controller.state.value.locationMutationBlockedMessage)
    }
    @Test fun importPinsRevisionBeforePickerAndRetainsSameInputRetryUntilExplicitReopen() = runBlocking {
        val controller = MainController()
        controller.mutableState.value = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        var committed = ControlCommitted("owner", 1, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS))
        val work = mutableListOf<suspend () -> Unit>()
        val requests = mutableListOf<ControlRequest>()
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add, { committed }, { request ->
            requests += request; ControlResult("owner", request.requestId, ControlCode.CONFLICT, committed.revision)
        })
        var pickers = 0
        frontend.beginImport { pickers++ }; assertEquals(0, pickers); work.removeAt(0)(); assertEquals(1, pickers)
        committed = committed.copy(revision = 2)
        frontend.import("private input"); work.removeAt(0)()
        frontend.import("private input"); work.removeAt(0)()
        assertEquals(1L, requests[0].ifRevision); assertEquals(requests[0], requests[1])
        frontend.cancelImport(); frontend.import("other input")
        assertTrue(work.isEmpty()); assertEquals(2, requests.size)
        frontend.beginImport { pickers++ }; work.removeAt(0)()
        frontend.import("private input"); work.removeAt(0)()
        assertEquals(2L, requests.last().ifRevision); assertNotEquals(requests[0].requestId, requests.last().requestId)
    }
    @Test fun explicitSelectionClickCanRecoverFinalConflictButUncertainRetryRetainsIdentity() = runBlocking {
        val raw = "socks://127.0.0.1:1080#Candidate"
        val controller = MainController()
        controller.mutableState.value = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(raw))
        var committed = ControlCommitted("owner", 1, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = listOf(raw)))
        val work = mutableListOf<suspend () -> Unit>()
        val requests = mutableListOf<ControlRequest>()
        var code = ControlCode.CONFLICT
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add, { committed }, { request ->
            requests += request
            ControlResult("owner", request.requestId, code, committed.revision, final = code != ControlCode.TIMEOUT)
        })
        frontend.select(raw); work.removeAt(0)()
        assertEquals(1, requests.size)
        committed = committed.copy(revision = 2)
        code = ControlCode.TIMEOUT
        frontend.select(raw); work.removeAt(0)()
        assertNotEquals(requests[0].requestId, requests[1].requestId)
        assertEquals(2L, requests[1].ifRevision)
        committed = committed.copy(revision = 3)
        frontend.select(raw); work.removeAt(0)()
        assertEquals(requests[1], requests[2])
    }

    @Test fun subscriptionEditorRemainsReadableButSaveCannotWriteReadOnlyRows() = runBlocking {
        val raw = "socks://127.0.0.1:1080#ReadOnly"
        val controller = MainController()
        controller.mutableState.value = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, currentLocations = listOf(raw))
        val work = mutableListOf<suspend () -> Unit>()
        var requests = 0
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add,
            { ControlCommitted("owner", 1, PersistedState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, currentLocations = listOf(raw))) },
            { request -> requests++; ControlResult("owner", request.requestId, ControlCode.UNSUPPORTED, 1) })
        frontend.open(raw); work.removeAt(0)()
        assertTrue(controller.state.value.showLocationDialog)
        assertTrue(controller.state.value.locationDraft.contains("ReadOnly"))
        assertEquals(0, requests)
        frontend.save(); work.removeAt(0)()
        assertEquals("UNSUPPORTED", controller.state.value.locationMutationBlockedMessage)
        assertTrue(controller.state.value.showLocationDialog)
    }

    @Test fun localEditorCapturesRevisionRetainsInputAndRetriesSameIdentityUntilExplicitReopen() = runBlocking {
        val controller = MainController()
        controller.mutableState.value = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        var snapshot = ControlCommitted("owner", 3, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS))
        val work = mutableListOf<suspend () -> Unit>()
        val requests = mutableListOf<ControlRequest>()
        var code = ControlCode.CONFLICT
        val frontend = AndroidGuiLocationActions(controller, { controller.state.value }, work::add, { snapshot }, { request ->
            requests += request
            ControlResult("owner", request.requestId, code, snapshot.revision)
        })
        frontend.open(); work.removeAt(0)()
        controller.onLocationDraftChanged("socks://127.0.0.1:1080#Private")
        snapshot = snapshot.copy(revision = 4)
        frontend.save(); work.removeAt(0)()
        frontend.save(); work.removeAt(0)()
        assertEquals(requests[0], requests[1]); assertEquals(3L, requests[0].ifRevision)
        assertTrue(controller.state.value.showLocationDialog)
        assertEquals("socks://127.0.0.1:1080#Private", controller.state.value.locationDraft)
        assertEquals("CONFLICT", controller.state.value.locationMutationBlockedMessage)
        controller.onLocationDraftChanged("socks://127.0.0.1:1081#Changed")
        frontend.save(); work.removeAt(0)()
        assertNotEquals(requests[0].requestId, requests.last().requestId)
        frontend.close(); frontend.open(); work.removeAt(0)()
        controller.onLocationDraftChanged("socks://127.0.0.1:1080#Private")
        code = ControlCode.OK
        frontend.save(); work.removeAt(0)()
        assertEquals(4L, requests.last().ifRevision)
        assertFalse(controller.state.value.showLocationDialog)
    }
}
