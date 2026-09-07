package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidSshDraftControlTest {
    @Test fun openingRevisionIsKeptAcrossExternalSaveAndPickerCompletion() = runTest {
        var state = ControlCommitted("owner", 1L, PersistedState())
        val requests = mutableListOf<ControlRequest>()
        val draft = AndroidSshDraftControl({ state }) { request ->
            requests += request
            ControlResult("owner", request.requestId,
                if (request.ifRevision == state.revision) ControlCode.OK else ControlCode.CONFLICT, state.revision)
        }
        draft.open()
        draft.beginKeyPicker()
        state = state.copy(revision = 2)
        assertEquals(ControlCode.CONFLICT, draft.save(HomeSshRouteSettings(host = "local-draft")).code)
        assertEquals(ControlCode.CONFLICT, draft.importKey("PRIVATE_TEST_KEY").code)
        assertEquals(listOf(1L, 1L), requests.map { it.ifRevision })
        assertEquals(listOf("owner", "owner"), requests.map { it.controllerId })
    }

    @Test fun responseLossRetryKeepsRequestIdentityAndPickerDoesNotRebaseOpenDraft() = runTest {
        var state = ControlCommitted("owner", 1L, PersistedState())
        val requests = mutableListOf<ControlRequest>()
        val draft = AndroidSshDraftControl({ state }) { request ->
            requests += request
            if (requests.size == 1) throw java.io.IOException("lost response")
            ControlResult("owner", request.requestId, ControlCode.OK, state.revision)
        }
        draft.open(); draft.beginKeyPicker()
        try { draft.importKey("PRIVATE_TEST_KEY") } catch (_: java.io.IOException) { }
        state = state.copy(revision = 2)
        draft.importKey("PRIVATE_TEST_KEY")
        assertEquals(requests[0], requests[1])
        draft.save(HomeSshRouteSettings())
        assertEquals(1L, requests.last().ifRevision)
    }
}
