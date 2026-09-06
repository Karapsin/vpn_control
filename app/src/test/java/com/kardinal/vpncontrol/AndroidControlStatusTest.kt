package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidControlStatusTest {
    private val request = ControlRequest("status", ControlCommand(ControlOperationId.STATUS))

    @Test fun stoppedIgnoresPersistedRunningAndExposesOnlyOpaqueSelectedIdentity() = runTest {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val state = PersistedState(isVpnRunning = true, selectedProfileRawLink = "secret://selected")
        val reader = reader(observer, state)
        val result = reader.read(request)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(9L, result.configurationRevision)
        assertEquals(ControlValue.BooleanValue(false), result.data["runtimeRunning"])
        assertEquals(ControlValue.Null, result.data["activeLocationId"])
        assertEquals(ControlValue.Null, result.data["runtimeStartedAt"])
        assertFalse(result.restartRequired)
        assertFalse(result.data.toString().contains("secret"))
        assertEquals(result.data, reader.read(request).data)
    }

    @Test fun runningUsesExactPreparedLocationNotLaterSelectionAndNoopKeepsIdentity() = runTest {
        val observer = AndroidRuntimeObserver(clockMillis = { 123 }, idGenerator = { "actual-runtime" })
        val state = PersistedState(selectedProfileRawLink = "secret://old")
        val prepared = ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), state))
        val handle = Any()
        observer.started(handle, AppMode.VPN, "private-json", prepared)
        val matching = reader(observer, state).read(request)
        assertEquals(ControlCode.OK, matching.code)
        assertEquals(matching.data["selectedLocationId"], matching.data["activeLocationId"])
        assertFalse(matching.restartRequired)
        val changed = reader(observer, state.copy(selectedProfileRawLink = "secret://new", appMode = AppMode.PROXY_ONLY)).read(request)
        assertEquals(ControlCode.OK, changed.code)
        assertTrue(changed.restartRequired)
        assertNotEquals(changed.data["selectedLocationId"], changed.data["activeLocationId"])
        assertEquals(matching.data["activeLocationId"], changed.data["activeLocationId"])
        assertEquals(ControlValue.Text("vpn"), changed.data["activeMode"])
        assertEquals(ControlValue.Text("proxy-only"), changed.data["configuredMode"])
        assertEquals(ControlValue.IntegerValue(123), changed.data["runtimeStartedAt"])
        observer.started(handle, AppMode.VPN, "ignored", null)
        assertEquals(matching.data, reader(observer, state).read(request).data)
        assertFalse(changed.data.toString().contains("secret"))
    }

    @Test fun unknownOrUnmatchedRuntimeCannotClaimCompleteHealthyStatus() = runTest {
        val observer = AndroidRuntimeObserver()
        val reader = reader(observer, PersistedState())
        val unknown = reader.read(request)
        assertEquals(ControlCode.UNAVAILABLE, unknown.code)
        assertEquals(ControlValue.Null, unknown.data["runtimeRunning"])
        assertEquals(ControlValue.Null, unknown.data["restartRequired"])
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in unknown.warnings)
        observer.started(Any(), AppMode.VPN, "sticky-without-preparation")
        val unmatched = reader.read(request)
        assertEquals(ControlCode.UNAVAILABLE, unmatched.code)
        assertEquals(ControlValue.BooleanValue(true), unmatched.data["runtimeRunning"])
        assertEquals(ControlValue.Null, unmatched.data["activeLocationId"])
        observer.resetCompleted(false)
        assertEquals(ControlValue.Null, reader.read(request).data["runtimeRunning"])
    }

    private fun reader(observer: AndroidRuntimeObserver, state: PersistedState) = AndroidControlReader(
        "owner", { error("Only committed snapshot") },
        committedSnapshot = { ControlCommitted("owner", 9, state) },
        pendingRestart = observer::pendingRestart, statusSnapshot = observer::controlStatus,
    )
}
