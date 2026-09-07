package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import com.kardinal.vpncontrol.control.ControlCommitted

class AndroidSubscriptionRefreshControlTest {
    private val sources = listOf(SubscriptionSource(id = "a", url = "https://a.example"), SubscriptionSource(id = "b", url = "https://b.example"))
    private fun request(id: String = "refresh", revision: Long = 7, async: Boolean = false) = ControlRequest(id,
        ControlCommand(ControlOperationId.SUBSCRIPTIONS_REFRESH, mapOf("id" to ControlValue.Text("all"))),
        controllerId = "owner", ifRevision = revision, asynchronous = async)

    @Test fun partialRefreshCommitsOnceAndRetainsExactRevisionEvenSchedulingFails() = runTest {
        var state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        var commits = 0
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { source, _ ->
            if (source.id == "b") error("private URL secret") else listOf("opaque-location")
        }, { loaded, epoch, revision ->
            assertEquals("owner", epoch); assertEquals(7, revision)
            assertEquals(2, loaded.size); commits++
            state.copy(revision = 8).also { state = it }
        }, { true }, { _, _ -> error("schedule failed") })
        val result = control.execute(request(), "op", { _, _ -> }, { true })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(8, result.configurationRevision); assertEquals(1, commits)
        assertEquals(ControlValue.IntegerValue(1), result.data["refreshedCount"])
        assertTrue(result.warnings.containsAll(listOf("PARTIAL_REFRESH", "REFRESH_SCHEDULING_FAILED")))
        assertTrue(result.restartRequired)
        assertFalse(result.toString().contains("private URL"))
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun cancellationDedupAndWorkerPolicyUseOneOwnerLease() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        val jobs = AndroidCommandJobs(backgroundScope)
        var commits = 0; var fetched = 0
        val entered = CompletableDeferred<Unit>()
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { _, _ ->
            fetched++; entered.complete(Unit); awaitCancellation()
        }, { _, _, _ -> commits++; state }, { null }, { _, _ -> })
        val owner = AndroidSettingsControl("owner", backgroundScope, { state }, { _, _, _ -> error("not settings") },
            {}, { null }, mutationJobs = jobs, refresh = { control })
        assertEquals(ControlCode.CONFLICT, owner.execute(request("stale", 6)).code)
        assertEquals(0, fetched)
        val command = request(async = true)
        val accepted = owner.execute(command); entered.await()
        assertEquals(ControlCode.ACCEPTED, accepted.code)
        assertEquals(accepted.operationId, owner.execute(command).operationId)
        assertEquals(ControlCode.CONFLICT, owner.execute(command) { _, _, _ -> emptyList() }.code)
        assertEquals(accepted.operationId, owner.activeRefreshOperationId())
        assertEquals(ControlCode.BUSY, owner.execute(request("other")).code)
        val cancel = owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(requireNotNull(accepted.operationId)))), controllerId = "owner", ifRevision = 7))
        assertEquals(ControlCode.OK, cancel.code)
        assertEquals(ControlCode.CANCELLED, owner.execute(command).code)
        assertEquals(0, commits); assertFalse(jobs.busy.value)
        assertNull(owner.activeRefreshOperationId())
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun partialFetchCancellationRetainsEveryTargetWithoutClaimingCommit() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        val waiting = CompletableDeferred<Unit>()
        var commits = 0
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { source, _ ->
            if (source.id == "a") listOf("fetched-location") else { waiting.complete(Unit); awaitCancellation() }
        }, { _, _, _ -> commits++; state }, { false }, { _, _ -> })
        val operation = async { control.execute(request(), "target", { _, _ -> }, { true }) }
        waiting.await(); runCurrent()
        control.cancel("target")
        val result = operation.await()
        assertEquals(ControlCode.CANCELLED, result.code)
        assertEquals(0, commits)
        assertEquals(ControlValue.IntegerValue(0), result.data["refreshedCount"])
        val rows = (result.data["subscriptions"] as ControlValue.ArrayValue).values.map { (it as ControlValue.ObjectValue).values }
        assertEquals(listOf(ControlValue.Text("a"), ControlValue.Text("b")), rows.map { it["id"] })
        assertEquals(ControlValue.IntegerValue(1), rows[0]["locationCount"])
        assertEquals(ControlValue.Text(ControlCode.CANCELLED.wireName), rows[1]["code"])
        assertTrue(rows.all { it["committed"] == ControlValue.BooleanValue(false) })
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun commitBoundaryRejectsLateCancellationAndCallerDisconnectDoesNotStopCommit() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        val jobs = AndroidCommandJobs(backgroundScope)
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { _, _ -> listOf("opaque") },
            { _, _, _ -> entered.complete(Unit); release.await(); state.copy(revision = 8) }, { false }, { _, _ -> })
        val owner = AndroidSettingsControl("owner", backgroundScope, { state }, { _, _, _ -> error("not settings") },
            {}, { null }, mutationJobs = jobs, refresh = { control })
        val command = request()
        val waiter = launch { owner.execute(command) }
        entered.await(); waiter.cancel(); waiter.join()
        val id = requireNotNull(owner.operationIdForRequest(command.requestId))
        val cancel = owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = "owner", ifRevision = 7))
        assertNotEquals(ControlCode.OK, cancel.code)
        assertTrue(jobs.busy.value)
        release.complete(Unit)
        assertEquals(ControlCode.OK, owner.execute(command).code)
        assertFalse(jobs.busy.value)
    }
    @Test fun pendingSelectionRemovalNeverDeletesActiveArtifactsOrTelemetry() {
        assertFalse(AndroidRefreshCommitPolicy.deleteArtifacts(AndroidRuntimeKnowledge.RUNNING))
        assertFalse(AndroidRefreshCommitPolicy.deleteArtifacts(AndroidRuntimeKnowledge.UNKNOWN))
        assertTrue(AndroidRefreshCommitPolicy.deleteArtifacts(AndroidRuntimeKnowledge.STOPPED))
    }
    @Test fun refreshingAwayActiveAIsIndependentFromRemovingPendingB() {
        val a = com.kardinal.vpncontrol.data.LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1080#A")
        val b = com.kardinal.vpncontrol.data.LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1081#B")
        val subscriptions = listOf(sources[0].copy(cachedLocations = listOf(a)), sources[1].copy(cachedLocations = listOf(b)))
        val pending = PersistedState(subscriptions = subscriptions, activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
            profileSourceMode = ProfileSourceMode.SUBSCRIPTION, selectedProfileJson = b,
            selectedProfileRawLink = com.kardinal.vpncontrol.data.LocationConfigs.decodeStoredLocation(b).rawLink,
            selectedProfileSourceUrl = sources[1].url)
        assertFalse(AndroidRefreshCommitPolicy.selectedMissing(pending, listOf(subscriptions[0].copy(cachedLocations = emptyList()), subscriptions[1])))
        assertTrue(AndroidRefreshCommitPolicy.selectedMissing(pending, listOf(subscriptions[0], subscriptions[1].copy(cachedLocations = emptyList()))))
        assertFalse(AndroidRefreshCommitPolicy.deleteArtifacts(AndroidRuntimeKnowledge.RUNNING))
    }
    @Test fun targetsAreCapturedFromCommittedSelectionNotActualRuntimeSource() {
        val subscriptions = listOf(SubscriptionSource(id = "a", url = "https://a.example"), SubscriptionSource(id = "b", url = "https://b.example"))
        val state = PersistedState(subscriptions = subscriptions, activeSubscriptionId = "b", profileSourceMode = ProfileSourceMode.SUBSCRIPTION)
        assertEquals(listOf("b"), AndroidSubscriptionRefreshControl.targets(state, "active").map { it.id })
        assertEquals(listOf("a", "b"), AndroidSubscriptionRefreshControl.targets(state, "all").map { it.id })
        assertEquals("NOT_FOUND", runCatching { AndroidSubscriptionRefreshControl.targets(state, "missing") }.exceptionOrNull()?.message)
    }
    @Test fun downloadRouteUsesActualSshAndPortNotPendingAndRejectsDrift() {
        val pending = PersistedState(homeSshRouteSettings = HomeSshRouteSettings(host = "pending"), managementProxyPort = 1111)
        val active = pending.copy(homeSshRouteSettings = HomeSshRouteSettings(host = "active"))
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        observer.started(Any(), AppMode.VPN, "private", com.kardinal.vpncontrol.control.ControlRuntimeConfiguration.committed(
            MainUiStateProjector.mergePersistedState(MainUiState(), active)))
        val point = requireNotNull(observer.captureRuntime())
        val route = androidRefreshRouteState(pending, observer.state.value, point, 2222)
        assertEquals("active", route.homeSshRouteSettings.host)
        assertEquals(2222, route.managementProxyPort)
        assertTrue(runCatching { androidRefreshRouteState(pending, AndroidRuntimeObservation(), point, 2222) }.isFailure)
        observer.started(Any(), AppMode.VPN, "different", point.configuration)
        assertTrue(runCatching { androidRefreshRouteState(pending, observer.state.value, point, 2222) }.isFailure)
    }
    @Test fun allFailuresRetainPerSourceResultsAndNoopRevisionAndCaptureFetcherOnce() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        var prepared = 0; var commits = 0
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { _, _ -> error("Must use captured fetch") },
            { loads, _, _ -> commits++; assertEquals(2, loads.size); state }, { false }, { _, _ -> },
            prepareFetch = { _, _ -> prepared++; { _ -> error("fetch failed") } })
        val result = control.execute(request(), "operation", { _, _ -> }, { true })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(7, result.configurationRevision)
        assertEquals(ControlValue.IntegerValue(2), result.data["failedCount"])
        assertEquals(1, prepared); assertEquals(1, commits)
    }
    @Test fun scheduledRoutePreparationFailureStillSchedulesNextWithoutEffects() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        var scheduled = 0
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { _, _ -> error("No fetch") },
            { _, _, _ -> error("No commit") }, { null }, { _, background -> assertTrue(background); scheduled++ },
            prepareFetch = { _, _ -> error("RUNTIME_STATE_UNKNOWN") })
        val result = control.execute(request(), "operation", { _, _ -> }, { error("No commit admission") },
            continuation = { _, _, _ -> error("No runtime effects") })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(1, scheduled)
        assertEquals(ControlValue.BooleanValue(false), result.data["committed"])
        assertEquals(ControlCode.CONFLICT, control.execute(request().copy(ifRevision = 6), "stale", { _, _ -> }, { true },
            continuation = { _, _, _ -> emptyList() }).code)
        assertEquals(1, scheduled)
    }
    @Test fun cancelledScheduledAdmissionDoesNotFetchOrCommitButSchedulesNextInsideOwner() = runTest {
        val state = ControlCommitted("owner", 7L, PersistedState(subscriptions = sources))
        var scheduled = 0
        val control = AndroidSubscriptionRefreshControl("owner", { state }, { _, _ -> error("No fetch") },
            { _, _, _ -> error("No commit") }, { false }, { _, background -> assertTrue(background); scheduled++ })
        val result = control.execute(request(), "operation", { _, _ -> }, { error("No commit admission") },
            canFetch = { false }, continuation = { _, _, _ -> error("No runtime effects") })
        assertEquals(ControlCode.CANCELLED, result.code)
        assertEquals(1, scheduled)
        assertEquals(ControlValue.IntegerValue(2), result.data["cancelledCount"])
    }
}
