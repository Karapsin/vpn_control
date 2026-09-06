package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidSettingsControlTest {
    @Test fun keyImportSharesOwnerGuardsAndDeduplicationWithoutReturningKeyMaterial() = runTest {
        var committed = ControlCommitted("owner", 0, PersistedState())
        var imports = 0
        val control = AndroidSettingsControl("owner", backgroundScope, { committed },
            { _, _, _ -> error("Settings path must not run") }, {}, { false },
            importKey = { content, owner, revision ->
                check(owner == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                assertEquals("PRIVATE_SECRET", content)
                imports++
                committed = committed.copy(revision = committed.revision + 1,
                    value = committed.value.copy(homeSshRouteSettings = committed.value.homeSshRouteSettings.copy(credentialVersion = 1)))
                AndroidSettingsCommit(committed, false)
            })
        val command = ControlCommand(ControlOperationId.SSH_KEY_IMPORT, mapOf("input" to ControlValue.Text("PRIVATE_SECRET")))
        val request = ControlRequest("key", command, controllerId = "owner", ifRevision = 0)
        val result = control.execute(request)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(1, result.configurationRevision)
        assertEquals(mapOf("present" to ControlValue.BooleanValue(true)), result.data)
        assertEquals(result, control.execute(request))
        assertEquals(1, imports)
        assertFalse(ControlProtocolCodec.encodeResult(result).contains("PRIVATE_SECRET"))
        assertEquals(ControlCode.CONFLICT, control.execute(request.copy(requestId = "stale")).code)
        assertEquals(1, imports)
        assertEquals(ControlCode.INVALID_ARGUMENT, control.execute(request.copy(requestId = "invalid",
            command = command.copy(arguments = mapOf("input" to ControlValue.Null)))).code)
    }
    @Test fun sharedLeaseExcludesTrackedGuiAndWorkerBothDirectionsButAllowsRetry() = runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val release = CompletableDeferred<Unit>()
        val fixture = Fixture(backgroundScope, jobs = jobs) { release.await() }
        val request = request("shared", "refresh.policy", "every-hour", 0)
        val waiter = async { fixture.control.execute(request) }
        runCurrent()
        assertTrue(jobs.busy.value)
        jobs.setBusy(false)
        assertNull(jobs.launchTracked { fail("settings owns admission") })
        assertNull(jobs.runTracked { Unit })
        jobs.cancelActive() // Non-cancellable settings are not the GUI's active job.
        val retry = async { fixture.control.execute(request) }
        runCurrent()
        assertFalse(retry.isCompleted)
        waiter.cancel()
        runCurrent()
        assertTrue(jobs.busy.value)
        release.complete(Unit)
        assertEquals(ControlCode.OK, retry.await().code)
        runCurrent()
        assertFalse(jobs.busy.value)
        val guiRelease = CompletableDeferred<Unit>()
        jobs.launchTracked { guiRelease.await() }
        assertEquals(ControlCode.BUSY, fixture.control.execute(request("blocked", "mode", "proxy-only", 1)).code)
        assertEquals(ControlCode.OK, fixture.control.execute(request).code)
        guiRelease.complete(Unit)
        runCurrent()
        assertEquals(ControlCode.OK, fixture.control.execute(request("after", "mode", "proxy-only", 1)).code)
    }

    @Test fun closedSettingsScopeReleasesSharedAdmission() = runTest {
        val closed = CoroutineScope(SupervisorJob()).apply { cancel() }
        val jobs = AndroidCommandJobs(backgroundScope)
        val fixture = Fixture(closed, jobs = jobs)
        assertEquals(ControlCode.CANCELLED, fixture.control.execute(request("closed-shared", "mode", "proxy-only", 0)).code)
        assertFalse(jobs.busy.value)
        assertNotNull(jobs.launchTracked {})
    }
    @Test fun freshOwnerProviderSettingsWorkWithoutStartingVpnDespiteStaleTelemetry() = runTest {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val fixture = Fixture(backgroundScope, pending = observer::pendingRestart)
        fixture.committed = fixture.committed.copy(value = fixture.committed.value.copy(isVpnRunning = true))
        val reader = AndroidControlReader("owner", { fixture.committed.value },
            committedSnapshot = { fixture.committed }, pendingRestart = observer::pendingRestart,
            settingsWrite = fixture.control::execute)
        val result = reader.read(request("fresh", "mode", "proxy-only", 0))
        assertEquals(ControlCode.OK, result.code)
        assertEquals(1, result.configurationRevision)
        assertFalse(result.restartRequired)
        assertFalse("PENDING_RESTART_STATE_UNAVAILABLE" in result.warnings)
        assertEquals(AndroidRuntimeKnowledge.STOPPED, observer.state.value.knowledge)
        assertNull(observer.state.value.runtimeId)
        assertNull(observer.state.value.stoppedAtEpochMillis)
    }

    @Test fun knownRunningSettingsBecomePendingWithoutReplacingRuntimeAndRevertClearsPending() = runTest {
        val observer = AndroidRuntimeObserver()
        val active = ControlRuntimeConfiguration.committed(MainUiState())
        observer.started(Any(), AppMode.VPN, "actual-config", active)
        val runtimeId = observer.state.value.runtimeId
        val fixture = Fixture(backgroundScope, pending = observer::pendingRestart)
        val changed = fixture.control.execute(request("change", "mode", "proxy-only", 0))
        assertEquals(ControlCode.OK, changed.code)
        assertTrue(changed.restartRequired)
        val rejected = fixture.control.execute(request("stale-owner", "mode", "vpn", 1).copy(controllerId = "old"))
        assertEquals(ControlCode.CONFLICT, rejected.code)
        assertTrue(rejected.restartRequired)
        assertEquals(1, rejected.configurationRevision)
        assertEquals(runtimeId, observer.state.value.runtimeId)
        assertFalse(fixture.control.execute(request("revert", "mode", "vpn", 1)).restartRequired)
        assertEquals(runtimeId, observer.state.value.runtimeId)
    }

    @Test fun unknownRuntimeRejectsBeforeEffectsAndConcurrentUnknownAfterCommitIsExplicit() = runTest {
        val observer = AndroidRuntimeObserver()
        val gate = CompletableDeferred<Unit>()
        val fixture = Fixture(backgroundScope, pending = observer::pendingRestart) { gate.await() }
        val unavailable = fixture.control.execute(request("unknown", "mode", "proxy-only", 0))
        assertEquals(ControlCode.UNAVAILABLE, unavailable.code)
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in unavailable.warnings)
        assertEquals(0, fixture.writes)
        observer.resetCompleted(true)
        val pending = async { fixture.control.execute(request("accepted", "refresh.policy", "every-hour", 0)) }
        runCurrent()
        assertEquals(1, fixture.writes)
        observer.started(Any(), AppMode.PROXY_ONLY, "sticky-config-without-descriptor")
        gate.complete(Unit)
        val result = pending.await()
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(1, result.configurationRevision)
        assertEquals(ControlValue.BooleanValue(true), result.data["configurationCommitted"])
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in result.warnings)
        assertEquals(result, fixture.control.execute(request("accepted", "refresh.policy", "every-hour", 0)))
    }

    @Test fun disconnectedWaiterAndDuplicateRequestDoNotRepeatCommittedEffects() = runTest {
        val scheduling = CompletableDeferred<Unit>()
        val fixture = Fixture(backgroundScope) { scheduling.await() }
        val request = request("same", "refresh.policy", "every-hour", 0)
        val disconnected = launch { fixture.control.execute(request) }
        runCurrent()
        assertEquals(1, fixture.writes)
        disconnected.cancel()
        val duplicate = async { fixture.control.execute(request) }
        runCurrent()
        assertFalse(duplicate.isCompleted)
        assertEquals(ControlCode.CONFLICT, fixture.control.execute(request("same", "refresh.policy", "off", 0)).code)
        assertEquals(ControlCode.BUSY, fixture.control.execute(request("other", "mode", "proxy-only", 1)).code)
        scheduling.complete(Unit)
        val completed = duplicate.await()
        assertEquals(ControlCode.OK, completed.code)
        assertEquals(1, completed.configurationRevision)
        assertEquals(completed, fixture.control.execute(request))
        assertEquals(1, fixture.writes)
        assertEquals(1, fixture.schedules)
    }

    @Test fun runtimeLosingAuthorityAfterAdmissionRejectsInsideAtomicCommitBeforeEffects() = runTest {
        var known = true
        val fixture = Fixture(backgroundScope, pending = { if (known) false else null })
        val request = request("guard-race", "mode", "proxy-only", 0)
        val result = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { fixture.control.execute(request) }
        known = false // Accepted owner job has not entered the serialized commit yet.
        runCurrent()
        val failed = result.await()
        assertEquals(ControlCode.RUNTIME_FAILED, failed.code)
        assertTrue("CONFIGURATION_NOT_COMMITTED" in failed.warnings)
        assertEquals(0, fixture.writes)
        assertEquals(0, failed.configurationRevision)
        assertEquals(failed, fixture.control.execute(request))
    }

    @Test fun noOpDoesNotResetSchedulingAndStaleGuardsRejectBeforeCommit() = runTest {
        val fixture = Fixture(backgroundScope)
        val first = fixture.control.execute(request("first", "refresh.policy", "every-hour", 0))
        assertEquals(ControlCode.OK, first.code)
        assertEquals(ControlCode.OK, fixture.control.execute(request("noop", "refresh.policy", "every-hour", 1)).code)
        assertEquals(1, fixture.writes)
        assertEquals(1, fixture.schedules)
        assertEquals(ControlCode.CONFLICT, fixture.control.execute(request("stale", "mode", "proxy-only", 0)).code)
        assertEquals(ControlCode.CONFLICT, fixture.control.execute(request("epoch", "mode", "proxy-only", 1).copy(controllerId = "old")).code)
        assertEquals(AppMode.VPN, fixture.committed.value.appMode)
    }

    @Test fun schedulingFailureRetainsDurableConfigurationAndExactTerminalRevision() = runTest {
        val fixture = Fixture(backgroundScope) { error("private-scheduler-error") }
        val request = request("failure", "refresh.policy", "every-hour", 0)
        val failed = fixture.control.execute(request)
        assertEquals(ControlCode.RUNTIME_FAILED, failed.code)
        assertEquals(1, failed.configurationRevision)
        assertEquals(ControlValue.BooleanValue(true), failed.data["configurationCommitted"])
        assertTrue("SCHEDULING_FAILED_OR_UNKNOWN" in failed.warnings)
        assertEquals(SubscriptionRefreshPolicy.EVERY_HOUR, fixture.committed.value.subscriptionRefreshPolicy)
        assertFalse(ControlProtocolCodec.encodeResult(failed).contains("private-scheduler-error"))
        assertEquals(failed, fixture.control.execute(request))
        assertEquals(1, fixture.schedules)
    }

    @Test fun returnedNormalizedResultBelongsToTheCommitNotALaterWriter() = runTest {
        val fixture = Fixture(backgroundScope)
        val request = request("first", "mode", "proxy-only", 0)
        val first = fixture.control.execute(request)
        assertEquals(ControlValue.Text("proxy-only"), first.data["mode"])
        assertEquals(setOf("mode"), first.data.keys)
        fixture.control.execute(request("second", "mode", "vpn", 1))
        assertEquals(2, fixture.committed.revision)
        assertEquals(first, fixture.control.execute(request))
        assertEquals(1, fixture.control.execute(request).configurationRevision)
    }

    @Test fun alreadyClosedOwnerCompletesAdmissionWithoutHangingOrWriting() = runTest {
        val closed = CoroutineScope(SupervisorJob()).apply { cancel() }
        val fixture = Fixture(closed)
        val request = request("closed", "mode", "proxy-only", 0)
        val result = fixture.control.execute(request)
        assertEquals(ControlCode.CANCELLED, result.code)
        assertEquals(0, fixture.writes)
        assertEquals(result, fixture.control.execute(request))
    }

    private class Fixture(scope: CoroutineScope, pending: (PersistedState) -> Boolean? = { false }, jobs: AndroidCommandJobs? = null, scheduling: suspend () -> Unit = {}) {
        var committed = ControlCommitted("owner", 0L, PersistedState(subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF))
        var writes = 0
        var schedules = 0
        val control = AndroidSettingsControl("owner", scope, snapshot = { committed }, commit = { patch, epoch, revision ->
            check(epoch == "owner" && (revision == null || revision == committed.revision)) { "CONFLICT" }
            check(pending(committed.value) != null) { "RUNTIME_STATE_UNKNOWN" }
            val prior = committed.value
            val plan = ControlSettingsLogic.plan(prior, patch, ControlPlatform.ANDROID, false)
            val next = (plan as? ControlSettingsPlan.Configuration)?.state ?: error("INVALID_ARGUMENT")
            if (ControlConfigurationIdentity.of(prior) != ControlConfigurationIdentity.of(next)) {
                committed = ControlCommitted("owner", committed.revision + 1, next)
                writes++
            }
            AndroidSettingsCommit(committed, prior.subscriptionRefreshPolicy != next.subscriptionRefreshPolicy ||
                prior.subscriptionRefreshCustomHours != next.subscriptionRefreshCustomHours)
        }, schedule = { schedules++; scheduling() }, pendingRestart = pending,
            busy = { jobs?.busy?.value ?: false }, mutationJobs = jobs)
    }

    private fun request(id: String, key: String, value: String, revision: Long) = ControlRequest(id,
        ControlCommand(ControlOperationId.SETTINGS_SET, mapOf("key" to ControlValue.Text(key), "value" to ControlValue.Text(value))),
        controllerId = "owner", ifRevision = revision)
}
