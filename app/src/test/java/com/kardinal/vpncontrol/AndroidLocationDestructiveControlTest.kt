package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidLocationDestructiveControlTest {
    private class Fixture {
        val a = LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1080#A")
        val b = LocationConfigs.normalizeStoredReference("socks://127.0.0.1:1081#B")
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        var committed = ControlCommitted("owner", 0, PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(a, b), savedLocations = listOf(a, b), selectedProfileJson = b,
            selectedProfileRawLink = LocationConfigs.decodeStoredLocation(b).rawLink))
        var stops = 0; var restores = 0; var writes = 0
        var onStop: suspend () -> Unit = {}
        var failure: String? = null
        var stopFailure: Throwable? = null
        init { start(a) }
        fun start(raw: String, source: String = "") {
            val active = committed.value.copy(selectedProfileJson = raw,
                selectedProfileRawLink = LocationConfigs.decodeStoredLocation(raw).rawLink, selectedProfileSourceUrl = source)
            observer.started(Any(), active.appMode, "EXACT_PRIVATE_A_CONFIG",
                ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), active)))
        }
        val executor = AndroidLocationDestructiveControl("owner", { committed }, { observer.state.value }, observer::captureRuntime,
            { expected ->
                check(observer.state.value == expected)
                stopFailure?.let { throw it }
                stops++; observer.resetCompleted(true); onStop(); Result.success(Unit)
            }, { plan, epoch, revision, expected ->
                check(epoch == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                check(expected == observer.state.value) { "RUNTIME_COMMAND_STALE" }
                failure?.let { error(it) }
                writes++
                val rows = requireNotNull(plan.locations)
                var next = committed.value.copy(currentLocations = rows, savedLocations = rows)
                if (next.selectedProfileSourceUrl.isBlank() && LocationConfigs.normalizeStoredReference(next.selectedProfileJson) !in rows)
                    next = next.copy(selectedProfileJson = "", selectedProfileRawLink = "")
                committed = committed.copy(revision = committed.revision + if (next == committed.value) 0 else 1, value = next)
                AndroidSettingsCommit(committed, false)
            }, { point, expected ->
                check(observer.state.value == expected); restores++
                observer.started(Any(), point.configuration.mode, point.runtimeJson, point.configuration); Result.success(Unit)
            }, observer::pendingRestart)
        fun delete(raw: String) = ControlRequest("delete", ControlCommand(ControlOperationId.LOCATIONS_DELETE,
            mapOf("id" to ControlValue.Text(AndroidLocationControl.identity("owner", committed.value, raw)))), controllerId = "owner", ifRevision = committed.revision)
    }

    @Test fun deletingPendingBLeavesActualAAndDeletingActualAKeepsPendingB() = runTest {
        val pending = Fixture(); val running = pending.observer.state.value
        assertEquals(ControlCode.OK, pending.executor.execute(pending.delete(pending.b), "operation").code)
        assertEquals(0, pending.stops); assertEquals(running, pending.observer.state.value)
        assertEquals("", pending.committed.value.selectedProfileJson)
        val active = Fixture()
        assertEquals(ControlCode.OK, active.executor.execute(active.delete(active.a), "operation").code)
        assertEquals(1, active.stops); assertEquals(active.b, active.committed.value.selectedProfileJson)
    }

    @Test fun staleCommitAfterStopRestoresOnlyExactRuntimeAndKeepsNewerSettings() = runTest {
        val f = Fixture(); val original = requireNotNull(f.observer.captureRuntime())
        f.onStop = { f.committed = f.committed.copy(revision = 7, value = f.committed.value.copy(appMode = AppMode.PROXY_ONLY,
            routingRules = f.committed.value.routingRules.copy(ignoreRules = false))) }
        val result = f.executor.execute(f.delete(f.a), "operation")
        assertEquals(ControlCode.CONFLICT, result.code); assertEquals(7L, result.configurationRevision)
        assertEquals(listOf("RUNTIME_RESTORED"), result.warnings)
        assertEquals(1, f.restores); assertEquals(0, f.writes)
        assertEquals(AppMode.PROXY_ONLY, f.committed.value.appMode); assertFalse(f.committed.value.routingRules.ignoreRules)
        assertEquals(original.runtimeJson, f.observer.captureRuntime()?.runtimeJson)
        assertEquals(original.configuration, f.observer.captureRuntime()?.configuration)
        assertEquals("AndroidRuntimeRestorePoint(<redacted>)", original.toString())
    }

    @Test fun foreignSourceAndMissingActiveRowDoNotStopAndStaleRequestDoesNothing() = runTest {
        val f = Fixture(); f.observer.resetCompleted(true); f.start(f.a, "https://source.invalid")
        assertEquals(ControlCode.CONFLICT, f.executor.execute(f.delete(f.a).copy(ifRevision = 99), "stale").code)
        assertEquals(0, f.stops); assertEquals(0, f.writes)
        assertEquals(ControlCode.OK, f.executor.execute(f.delete(f.a), "delete").code)
        assertEquals(0, f.stops)
    }

    @Test fun importsIndependentlyPreserveActiveAndPendingAndNoOpRevision() = runTest {
        for (keepActive in listOf(true, false)) {
            val f = Fixture()
            val result = f.executor.execute(ControlRequest("import", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text(if (keepActive) f.a else f.b))), controllerId = "owner"), "operation")
            assertEquals(ControlCode.OK, result.code)
            assertEquals(if (keepActive) 0 else 1, f.stops)
            assertEquals(if (keepActive) "" else f.b, f.committed.value.selectedProfileJson)
            assertEquals(ControlValue.IntegerValue(1), result.data["importedLocations"])
            val revision = result.configurationRevision
            val noop = f.executor.execute(ControlRequest("again", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text(if (keepActive) f.a else f.b))), controllerId = "owner"), "again")
            assertEquals(revision, noop.configurationRevision)
        }
    }

    @Test fun cancelledWaiterCannotAbandonRecoveryAfterAcknowledgedStop() = runTest {
        val f = Fixture(); val gate = CompletableDeferred<Unit>(); val stopped = CompletableDeferred<Unit>()
        f.failure = "disk failure"
        f.onStop = { stopped.complete(Unit); gate.await() }
        val work = launch { f.executor.execute(f.delete(f.a), "operation") }
        stopped.await(); work.cancel(); runCurrent()
        assertEquals(0, f.restores)
        gate.complete(Unit); work.join()
        assertEquals(1, f.restores); assertEquals(0, f.writes)
        assertEquals(listOf(f.a, f.b), f.committed.value.currentLocations)
        assertEquals(AndroidRuntimeKnowledge.RUNNING, f.observer.state.value.knowledge)
    }

    @Test fun ownerRetryReturnsOriginalDeletionWithoutRepeatingStopOrRestoration() = runTest {
        val f = Fixture()
        val owner = AndroidSettingsControl("owner", backgroundScope, { f.committed }, { _, _, _ -> error("settings") }, {},
            f.observer::pendingRestart, locationRemoval = f.executor)
        val request = f.delete(f.a)
        val result = owner.execute(request)
        assertEquals(ControlCode.OK, result.code)
        f.committed = f.committed.copy(revision = 99)
        assertEquals(result, owner.execute(request))
        assertEquals(1, f.stops); assertEquals(1, f.writes); assertEquals(0, f.restores)
    }

    @Test fun failedOrUncertainStopNeverWritesOrBlindlyRestores() = runTest {
        for (failure in listOf(IllegalStateException("stop failed"), AndroidRuntimeOutcomeUnknownException())) {
            val f = Fixture(); f.stopFailure = failure
            val result = f.executor.execute(f.delete(f.a), "operation")
            assertEquals(ControlCode.RUNTIME_FAILED, result.code)
            assertEquals(listOf(if (failure is AndroidRuntimeOutcomeUnknownException) "RUNTIME_OUTCOME_UNKNOWN" else "RUNTIME_NOT_CHANGED"), result.warnings)
            assertTrue(result.data.isEmpty()); assertEquals(0, f.writes); assertEquals(0, f.restores)
        }
    }
}
