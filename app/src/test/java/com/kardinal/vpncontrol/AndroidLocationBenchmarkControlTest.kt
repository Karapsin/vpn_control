package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

class AndroidLocationBenchmarkControlTest {
    private val z = "socks://127.0.0.1:1080#Zulu"
    private val a = "socks://127.0.0.1:1081#Alpha"
    private val state = ControlCommitted("owner", 7L, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
        currentLocations = listOf(z, a), savedLocations = listOf(z, a)))
    private fun request(id: String = "check", revision: Long = 7, async: Boolean = false) = ControlRequest(id,
        ControlCommand(ControlOperationId.LOCATIONS_BENCHMARK, mapOf("selector" to ControlValue.Text("1"))),
        controllerId = "owner", ifRevision = revision, asynchronous = async)
    private fun benchmark(raw: String) = ProfileBenchmark(LocationConfigs.decodeStoredLocation(raw), "ok", "ok", 12.0, 13.0, 1.0, "private detail")

    @Test fun subscriptionVisibleStableIdAndSelectorResolveTheSameLocation() {
        val subscribed = state.value.copy(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = "sub", profileUrl = "https://example.test/sub", savedLocations = emptyList(),
            subscriptions = listOf(SubscriptionSource(id = "sub", url = "https://example.test/sub", cachedLocations = listOf(z, a))))
        val id = com.kardinal.vpncontrol.data.AndroidLocationControl.identity("owner", subscribed, a)
        assertEquals(a, AndroidLocationBenchmarkControl.target(subscribed, mapOf("id" to ControlValue.Text(id)), "owner"))
        assertEquals(a, AndroidLocationBenchmarkControl.target(subscribed, mapOf("selector" to ControlValue.Text("1")), "owner"))
        assertTrue(runCatching { AndroidLocationBenchmarkControl.target(subscribed.copy(profileUrl = "https://changed.test"),
            mapOf("id" to ControlValue.Text(id)), "owner") }.isFailure)
    }

    @Test fun visibleTargetIsCapturedAndTelemetryCompletionKeepsConfigurationRevision() = runTest {
        var probes = 0; var commits = 0
        val progress = mutableListOf<Pair<Long, Long>>()
        val control = AndroidLocationBenchmarkControl("owner", { state }, { raw, captured ->
            probes++; assertEquals(a, raw); assertEquals(state.value, captured); benchmark(raw)
        }, { raw, result, epoch, revision ->
            commits++; assertEquals(a, raw); assertEquals(12.0, result.primaryTotal!!, 0.0)
            assertEquals("owner", epoch); assertEquals(7L, revision); state
        }, { true })
        assertEquals(ControlCode.CONFLICT, control.execute(request(revision = 6), "stale", { _, _ -> }, { true }).code)
        assertEquals(0, probes)
        val result = control.execute(request(), "op", { done, total -> progress += done to total }, { true })
        assertEquals(ControlCode.OK, result.code); assertEquals(7L, result.configurationRevision)
        assertEquals(1, probes); assertEquals(1, commits); assertTrue(result.restartRequired)
        assertEquals(listOf(0L to 1L, 1L to 1L), progress)
        assertFalse(result.toString().contains("private detail"))
    }

    @Test fun persistenceFailureIsNotBenchmarkSuccessAndCancelledCommitWritesNothing() = runTest {
        var commits = 0
        val control = AndroidLocationBenchmarkControl("owner", { state }, { raw, _ -> benchmark(raw) },
            { _, _, _, _ -> commits++; error("private path") }, { false })
        assertEquals(ControlCode.CANCELLED, control.execute(request(), "one", { _, _ -> }, { false }).code)
        assertEquals(0, commits)
        val failed = control.execute(request(), "two", { _, _ -> }, { true })
        assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code)
        assertEquals(ControlValue.BooleanValue(false), failed.data["committed"])
        assertFalse(failed.toString().contains("private path"))
    }

    @Test fun measuredTimeoutIsRetainedButReportedAsRuntimeFailure() = runTest {
        val measured = benchmark(a).copy(secondaryStatus = "timeout", secondaryTotal = null)
        var commits = 0
        val progress = mutableListOf<Pair<Long, Long>>()
        val control = AndroidLocationBenchmarkControl("owner", { state }, { raw, captured ->
            assertEquals(a, raw)
            assertEquals(state.value, captured)
            measured
        }, { raw, result, epoch, revision ->
            assertEquals(a, raw)
            assertEquals(measured, result)
            assertEquals("owner", epoch)
            assertEquals(7L, revision)
            commits++
            state
        }, { true })

        val result = control.execute(request(), "timeout", { done, total -> progress += done to total }, { true })

        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertFalse(result.ok)
        assertEquals(ControlValue.BooleanValue(true), result.data["committed"])
        assertEquals(ControlValue.DecimalValue(12.0), result.data["primaryTotalMs"])
        assertEquals(ControlValue.Null, result.data["secondaryTotalMs"])
        assertEquals(7L, result.configurationRevision)
        assertTrue(result.restartRequired)
        assertEquals(1, commits)
        assertEquals(listOf(0L to 1L, 1L to 1L), progress)
        assertFalse(result.toString().contains("private detail"))
    }

    @Test fun ownerDeduplicatesAndExplicitCancellationWaitsForProbeCleanup() = runTest {
        var probes = 0; var commits = 0; var cleaned = false
        val entered = CompletableDeferred<Unit>()
        val control = AndroidLocationBenchmarkControl("owner", { state }, { _, _ ->
            probes++; entered.complete(Unit)
            try { awaitCancellation() } finally { cleaned = true }
        }, { _, _, _, _ -> commits++; state }, { false })
        val jobs = AndroidCommandJobs(backgroundScope)
        val owner = AndroidSettingsControl("owner", backgroundScope, { state }, { _, _, _ -> error("settings") },
            {}, { false }, mutationJobs = jobs, benchmark = { control })
        val command = request(async = true)
        val accepted = owner.execute(command); entered.await()
        assertEquals(ControlCode.ACCEPTED, accepted.code)
        assertEquals(accepted.operationId, owner.execute(command).operationId)
        assertEquals(ControlCode.BUSY, owner.execute(request("other")).code)
        val cancel = owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(requireNotNull(accepted.operationId)))), controllerId = "owner"))
        assertEquals(ControlCode.OK, cancel.code); assertTrue(cleaned)
        assertEquals(ControlCode.CANCELLED, owner.execute(command).code)
        assertEquals(1, probes); assertEquals(0, commits); assertFalse(jobs.busy.value)
    }

    @Test fun commitSurvivesWaiterDisconnectAndRejectsLateCancellation() = runTest {
        var commits = 0
        val entered = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        val jobs = AndroidCommandJobs(backgroundScope)
        val control = AndroidLocationBenchmarkControl("owner", { state }, { raw, _ -> benchmark(raw) },
            { _, _, _, _ -> commits++; entered.complete(Unit); release.await(); state }, { true })
        val owner = AndroidSettingsControl("owner", backgroundScope, { state }, { _, _, _ -> error("settings") },
            {}, { true }, mutationJobs = jobs, benchmark = { control })
        val waiter = launch { owner.execute(request()) }
        entered.await(); waiter.cancelAndJoin()
        val id = requireNotNull(owner.activeBenchmarkOperationId())
        val cancel = owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = "owner"))
        assertNotEquals(ControlCode.OK, cancel.code); assertTrue(jobs.busy.value)
        release.complete(Unit)
        val result = owner.execute(request())
        assertEquals(ControlCode.OK, result.code); assertTrue(result.restartRequired)
        assertEquals(7L, result.configurationRevision); assertEquals(1, commits)
        assertNull(owner.activeBenchmarkOperationId()); assertFalse(jobs.busy.value)
    }

    @Test fun snapshotFailureIsNotReportedAsFailedPersistence() = runTest {
        val control = AndroidLocationBenchmarkControl("owner", { error("private path") }, { _, _ -> error("probe") },
            { _, _, _, _ -> error("commit") }, { false })
        val result = control.execute(request(), "op", { _, _ -> }, { true })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertTrue("CONFIGURATION_REVISION_UNAVAILABLE" in result.warnings)
        assertFalse(result.toString().contains("private path"))
    }
}
