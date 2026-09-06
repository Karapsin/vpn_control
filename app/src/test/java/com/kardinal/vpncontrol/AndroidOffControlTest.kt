package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidOffControlTest {
    @Test fun stoppedOffIsIdempotentWithoutDispatchDespiteStalePersistedRunningFlag() = runTest {
        val fixture = Fixture(AndroidCommandJobs(backgroundScope))
        val reader = AndroidControlReader("owner", { fixture.committed.value }, settingsWrite = fixture.control::execute)
        val result = reader.read(request())
        assertEquals(ControlCode.OK, result.code)
        assertFalse(result.restartRequired)
        assertEquals(4, result.configurationRevision)
        assertEquals(0, fixture.stops)
        assertEquals(result, reader.read(request()))
    }

    @Test fun runningWithoutPreparedInputsStopsOnlyAfterAcknowledgmentAndSurvivesDisconnect() = runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val fixture = Fixture(jobs)
        fixture.observer.started(Any(), AppMode.VPN, "live-ssh-unknown-descriptor")
        val gate = CompletableDeferred<Unit>()
        fixture.stopBody = { gate.await(); fixture.observer.resetCompleted(true); Result.success(Unit) }
        val disconnected = async { fixture.control.execute(request()) }
        runCurrent()
        assertEquals(1, fixture.stops)
        assertNull(jobs.launchTracked {})
        disconnected.cancel()
        val retry = async { fixture.control.execute(request()) }
        runCurrent()
        assertFalse(retry.isCompleted)
        assertEquals(1, fixture.stops)
        gate.complete(Unit)
        val result = retry.await()
        assertEquals(ControlCode.OK, result.code)
        assertFalse(result.restartRequired)
        runCurrent()
        assertFalse(jobs.busy.value)
        assertEquals(result, fixture.control.execute(request()))
    }

    @Test fun staleGuardsBusyAndUnknownRejectBeforeNativeEffects() = runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val fixture = Fixture(jobs)
        fixture.observer.started(Any(), AppMode.VPN, "live")
        assertEquals(ControlCode.CONFLICT, fixture.control.execute(request().copy(controllerId = "old")).code)
        assertEquals(ControlCode.CONFLICT, fixture.control.execute(request("revision").copy(ifRevision = 3)).code)
        val lease = requireNotNull(jobs.tryAcquireMutation())
        assertEquals(ControlCode.BUSY, fixture.control.execute(request("busy")).code)
        jobs.releaseMutation(lease)
        fixture.observer.resetCompleted(false)
        assertEquals(ControlCode.UNAVAILABLE, fixture.control.execute(request("unknown")).code)
        assertEquals(0, fixture.stops)
    }

    @Test fun unconfirmedCleanupNeverReportsSuccessAndRetryNeverRedispatches() = runTest {
        val fixture = Fixture(AndroidCommandJobs(backgroundScope))
        fixture.observer.started(Any(), AppMode.VPN, "live")
        fixture.stopBody = { fixture.observer.resetCompleted(false); Result.success(Unit) }
        val result = fixture.control.execute(request())
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertTrue("RUNTIME_OUTCOME_UNKNOWN" in result.warnings)
        assertEquals(result, fixture.control.execute(request()))
        assertEquals(1, fixture.stops)
    }

    @Test fun expiredNativeWaitIsExplicitUnknownAndRetryCannotDispatchAgain() = runTest {
        val fixture = Fixture(AndroidCommandJobs(backgroundScope))
        fixture.observer.started(Any(), AppMode.VPN, "live")
        fixture.stopBody = { Result.failure(com.kardinal.vpncontrol.data.VpnCommandException(
            "receipt expired", AndroidRuntimeOutcomeUnknownException(), commandDispatched = true)) }
        val result = fixture.control.execute(request())
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertTrue("RUNTIME_OUTCOME_UNKNOWN" in result.warnings)
        fixture.observer.resetCompleted(true) // A later authoritative observation does not rewrite history.
        assertEquals(result, fixture.control.execute(request()))
        assertEquals(1, fixture.stops)
    }

    private class Fixture(jobs: AndroidCommandJobs) {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val committed = ControlCommitted("owner", 4L, PersistedState(isVpnRunning = true))
        var stops = 0
        var stopBody: suspend () -> Result<Unit> = { observer.resetCompleted(true); Result.success(Unit) }
        val off = AndroidOffControl("owner", { committed }, { observer.state.value }, { stops++; stopBody() }, observer::pendingRestart)
        val control = AndroidSettingsControl("owner", jobs.scope, { committed },
            commit = { _, _, _ -> error("OFF must not commit settings") }, schedule = {},
            pendingRestart = observer::pendingRestart, mutationJobs = jobs, busy = { jobs.busy.value }, off = off)
    }

    private fun request(id: String = "off") = ControlRequest(id, ControlCommand(ControlOperationId.OFF),
        controllerId = "owner", ifRevision = 4)
}
