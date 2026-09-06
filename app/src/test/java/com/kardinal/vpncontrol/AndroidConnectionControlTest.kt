package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidConnectionControlTest {
    @Test fun cancellationControlPlaneIsBoundedAndDuplicateDoesNotConsumeAnotherSlot() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        val requests = (0 until 32).map { operationRequest(ControlOperationId.OPERATIONS_CANCEL, "cancel-$it", "missing-$it") }
        val waiters = requests.map { request -> async(start = CoroutineStart.UNDISPATCHED) { f.control.execute(request) } }
        val retry = async(start = CoroutineStart.UNDISPATCHED) { f.control.execute(requests.first()) }
        assertEquals(ControlCode.BUSY, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_CANCEL, "overflow", "missing")).code)
        runCurrent()
        waiters.forEach { assertEquals(ControlCode.NOT_FOUND, it.await().code) }
        assertEquals(waiters.first().await(), retry.await())
        assertEquals(ControlCode.NOT_FOUND, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_CANCEL, "after", "missing")).code)
        assertFalse(f.jobs.busy.value)
    }
    @Test fun disconnectedCancellationWaiterDoesNotAbandonCleanupAndRetentionIsBounded() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.foreground = false
        val original = request().copy(interactive = true)
        val id = requireNotNull(f.control.execute(original).operationId)
        runCurrent()
        val cancel = operationRequest(ControlOperationId.OPERATIONS_CANCEL, "disconnect-cancel", id)
        val waiter = async(start = CoroutineStart.UNDISPATCHED) { f.control.execute(cancel) }
        waiter.cancel()
        runCurrent()
        assertFalse(f.jobs.busy.value)
        assertEquals(ControlCode.CANCELLED, f.control.execute(original).code)
        assertEquals(ControlCode.OK, f.control.execute(cancel).code)
        assertEquals(ControlCode.CONFLICT, f.control.execute(cancel.copy(requestId = "stale", controllerId = "old")).code)
        assertEquals(ControlCode.CONFLICT, f.control.execute(cancel.copy(requestId = "stale-revision", ifRevision = 0)).code)
        assertEquals(ControlCode.NOT_FOUND, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_CANCEL, "missing", "missing")).code)
        f.clock = 30 * 60 * 1000L
        val listed = f.control.execute(operationRequest(ControlOperationId.OPERATIONS_LIST, "expired"))
        assertEquals(emptyList<ControlValue>(), (listed.data.getValue("operations") as ControlValue.ArrayValue).values)
        assertEquals(ControlCode.NOT_FOUND, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_STATUS, "old-status", id)).code)
    }
    @Test fun consentCancellationListsRetainedResultAndReleasesLeaseBeforeAcknowledgment() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.foreground = false
        val original = request().copy(interactive = true)
        val accepted = f.control.execute(original)
        runCurrent()
        val id = requireNotNull(accepted.operationId)
        val token = requireNotNull(f.interactions.tokenFor(id))
        val listing = f.control.execute(operationRequest(ControlOperationId.OPERATIONS_LIST, "list"))
        assertEquals(ControlCode.OK, listing.code)
        val summary = ((listing.data.getValue("operations") as ControlValue.ArrayValue).values.single() as ControlValue.ObjectValue).values
        assertEquals(ControlValue.Text("awaiting-user"), summary["phase"])
        assertEquals(ControlValue.BooleanValue(true), summary["cancellable"])
        val cancel = operationRequest(ControlOperationId.OPERATIONS_CANCEL, "cancel", id)
        val acknowledged = f.control.execute(cancel)
        assertEquals(ControlCode.OK, acknowledged.code)
        assertFalse(f.jobs.busy.value)
        assertFalse(f.interactions.isActive(token))
        assertEquals(0, f.preparations)
        assertEquals(ControlCode.CANCELLED, f.control.execute(original).code)
        assertEquals(acknowledged, f.control.execute(cancel))
        assertEquals(ControlCode.CONFLICT, f.control.execute(cancel.copy(command = ControlCommand(
            ControlOperationId.OPERATIONS_CANCEL, mapOf("id" to ControlValue.Text("other"))))).code)
    }

    @Test fun approvalAndCancellationRaceStopsBeforePreparationOrRejectsAfterBoundary() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.foreground = false
        val original = request().copy(interactive = true)
        val id = requireNotNull(f.control.execute(original).operationId)
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor(id))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        f.foreground = true
        f.interactions.resolve(token, session, ControlCode.OK)
        // The grant callback completed, but the owner has not passed its atomic gate.
        assertEquals(ControlCode.OK, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_CANCEL, "race", id)).code)
        assertEquals(0, f.preparations)
        val gate = CompletableDeferred<Unit>()
        f.startGate = gate
        val running = async { f.control.execute(request(id = "second")) }
        runCurrent()
        val runningId = requireNotNull(f.control.operationIdForRequest("second"))
        assertEquals(ControlCode.CONFLICT, f.control.execute(operationRequest(ControlOperationId.OPERATIONS_CANCEL, "late", runningId)).code)
        assertTrue(f.jobs.busy.value)
        gate.complete(Unit)
        assertEquals(ControlCode.OK, running.await().code)
    }

    private fun operationRequest(operation: ControlOperationId, requestId: String, id: String? = null) =
        ControlRequest(requestId, ControlCommand(operation, id?.let { mapOf("id" to ControlValue.Text(it)) } ?: emptyMap()), controllerId = "owner")

    @Test fun noninteractiveMissingForegroundOrConsentHasNoPreparationEffects() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.foreground = false
        assertEquals(ControlCode.INTERACTION_REQUIRED, f.control.execute(request()).code)
        f.foreground = true
        f.prepared = false
        assertEquals(ControlCode.INTERACTION_REQUIRED, f.control.execute(request()).code)
        assertEquals(0, f.preparations)
        assertEquals(0, f.starts)
    }

    @Test fun interactiveGrantRecreationAndOperationWaitShareOneOwnerStart() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.foreground = false
        f.prepared = false
        val request = request().copy(interactive = true)
        val accepted = f.control.execute(request)
        assertEquals(ControlCode.ACCEPTED, accepted.code)
        runCurrent()
        val id = requireNotNull(accepted.operationId)
        val token = requireNotNull(f.interactions.tokenFor(id))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        assertEquals(session, f.interactions.attach(token, "owner", session))
        assertEquals(0, f.starts)
        val duplicate = f.control.execute(request)
        assertEquals(id, duplicate.operationId)
        val waitRequest = ControlRequest("wait", ControlCommand(ControlOperationId.OPERATIONS_WAIT,
            mapOf("id" to ControlValue.Text(id))), controllerId = "owner")
        val disconnected = async { f.control.execute(waitRequest) }
        runCurrent()
        disconnected.cancel()
        f.foreground = true
        f.prepared = true
        f.interactions.resolve(token, session, ControlCode.OK)
        runCurrent()
        val completed = f.control.execute(waitRequest.copy(requestId = "new-waiter"))
        assertEquals(ControlCode.OK, completed.code)
        assertEquals("new-waiter", completed.requestId)
        assertEquals(1, f.starts)
        assertEquals(1, f.persists)
        assertFalse(f.jobs.busy.value)
        assertEquals(ControlCode.OK, f.control.execute(request).code)
    }

    @Test fun denialAndRevocationBeforeDispatchDoNotReplaceRuntime() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.observer.started(Any(), AppMode.VPN, "old")
        val before = f.observer.state.value
        f.prepared = false
        val accepted = f.control.execute(request(ControlOperationId.RESTART).copy(interactive = true))
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor(requireNotNull(accepted.operationId)))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        f.interactions.resolve(token, session, ControlCode.PERMISSION_DENIED)
        runCurrent()
        assertEquals(ControlCode.PERMISSION_DENIED, f.control.execute(request(ControlOperationId.RESTART).copy(interactive = true)).code)
        assertEquals(before, f.observer.state.value)
        assertEquals(0, f.preparations)
    }

    @Test fun onNoopPreservesIdentityAndRestartValidationPrecedesReplacement() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.observer.started(Any(), AppMode.VPN, "old")
        val before = f.observer.state.value
        assertEquals(ControlCode.OK, f.control.execute(request()).code)
        assertEquals(before, f.observer.state.value)
        assertEquals(0, f.starts)
        f.invalidConfig = true
        assertEquals(ControlCode.INVALID_ARGUMENT, f.control.execute(request(ControlOperationId.RESTART, "restart")).code)
        assertEquals(before, f.observer.state.value)
        assertEquals(0, f.starts)
    }

    @Test fun staleGuardsAndBusyHaveNoEffectsAndPendingStartHoldsLease() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        assertEquals(ControlCode.CONFLICT, f.control.execute(request().copy(controllerId = "old")).code)
        assertEquals(ControlCode.CONFLICT, f.control.execute(request(id = "stale").copy(ifRevision = 0)).code)
        assertEquals(0, f.preparations)
        val gate = CompletableDeferred<Unit>()
        f.startGate = gate
        val waiting = async { f.control.execute(request(id = "running")) }
        runCurrent()
        assertFalse(waiting.isCompleted)
        assertNull(f.jobs.tryAcquireMutation())
        gate.complete(Unit)
        assertEquals(ControlCode.OK, waiting.await().code)
        assertEquals(1, f.starts)
    }

    @Test fun revocationAfterValidationAndDispatchFailureNeverClaimSuccessfulReplacement() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.observer.started(Any(), AppMode.VPN, "old")
        val before = f.observer.state.value
        f.afterValidation = { f.prepared = false }
        assertEquals(ControlCode.INTERACTION_REQUIRED,
            f.control.execute(request(ControlOperationId.RESTART, "revoked")).code)
        assertEquals(before, f.observer.state.value)
        assertEquals(0, f.persists)
        f.afterValidation = {}
        f.prepared = true
        f.startFailure = com.kardinal.vpncontrol.data.VpnCommandException("FGS rejected", commandDispatched = false)
        assertEquals(ControlCode.RUNTIME_FAILED, f.control.execute(request(ControlOperationId.RESTART, "fgs")).code)
        assertEquals(before, f.observer.state.value)
        f.startFailure = com.kardinal.vpncontrol.data.VpnCommandException("wait expired", AndroidRuntimeOutcomeUnknownException(), true)
        val unknown = f.control.execute(request(ControlOperationId.RESTART, "unknown"))
        assertEquals(ControlCode.RUNTIME_FAILED, unknown.code)
        assertTrue("RUNTIME_OUTCOME_UNKNOWN" in unknown.warnings)
        assertEquals(0, f.persists)
    }

    @Test fun proxyOnlyInteractionNeedsForegroundButNotVpnApproval() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.state = f.state.copy(value = f.state.value.copy(appMode = AppMode.PROXY_ONLY))
        f.foreground = false
        f.prepared = false
        val accepted = f.control.execute(request().copy(interactive = true))
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor(requireNotNull(accepted.operationId)))
        assertFalse(f.connection.requiresVpnConsent(token))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        f.foreground = true
        f.interactions.resolve(token, session, ControlCode.OK)
        runCurrent()
        assertEquals(ControlCode.OK, f.control.execute(request().copy(interactive = true)).code)
    }

    @Test fun failureAfterRuntimeAndDurableCommitRetainsActualRevisionWithoutRollback() = runTest {
        val f = Fixture(AndroidCommandJobs(backgroundScope))
        f.afterPersist = { f.state = f.state.copy(revision = 2); error("after commit") }
        val result = f.control.execute(request())
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(2, result.configurationRevision)
        assertTrue("RUNTIME_STARTED_PERSISTENCE_FAILED" in result.warnings)
        assertEquals(AndroidRuntimeKnowledge.RUNNING, f.observer.state.value.knowledge)
    }

    private class Fixture(val jobs: AndroidCommandJobs) {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val interactions = AndroidControlInteractions("owner")
        var state = ControlCommitted("owner", 1L, PersistedState())
        var foreground = true
        var prepared = true
        var invalidConfig = false
        var preparations = 0
        var starts = 0
        var persists = 0
        var startGate: CompletableDeferred<Unit>? = null
        var afterValidation: () -> Unit = {}
        var startFailure: Exception? = null
        var afterPersist: () -> Unit = {}
        var clock = 0L
        val connection = AndroidConnectionControl("owner", { state }, { observer.state.value },
            { foreground }, { prepared }, interactions,
            prepare = { preparations++; Result.success(selection()) },
            validate = { if (invalidConfig) error("invalid"); afterValidation() },
            start = { selection, eligible ->
                starts++; startGate?.await()
                if (!eligible()) Result.failure(IllegalStateException("not eligible"))
                else if (startFailure != null) Result.failure(requireNotNull(startFailure)) else {
                    observer.started(Any(), state.value.appMode, selection.runtimeConfigJson,
                        ControlRuntimeConfiguration.committed(MainUiState(appMode = state.value.appMode)))
                    Result.success(Unit)
                }
            }, persist = { persists++; afterPersist() }, pendingRestart = observer::pendingRestart)
        val control = AndroidSettingsControl("owner", jobs.scope, { state },
            commit = { _, _, _ -> error("unexpected settings") }, schedule = {},
            pendingRestart = observer::pendingRestart, mutationJobs = jobs, connection = connection, now = { clock })
    }

    companion object {
        private fun request(operation: ControlOperationId = ControlOperationId.ON, id: String = "start") =
            ControlRequest(id, ControlCommand(operation), controllerId = "owner", ifRevision = 1)
        private fun selection(): ProfileSelection {
            val profile = ProxyProfile(protocol = ProxyProtocol.SOCKS, remarks = "fixture", server = "127.0.0.1", serverPort = 1234,
                network = "tcp", flow = "", security = "", sni = "", fingerprint = "", publicKey = "", shortId = "",
                path = "", hostHeader = "", serviceName = "", headerType = "", rawLink = "socks://127.0.0.1:1234")
            return ProfileSelection(profile, ProfileBenchmark(profile, "ok", "ok", 1.0, 1.0, 1.0, "fixture"), "{}")
        }
    }
}
