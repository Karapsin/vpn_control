package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidFindBestControlTest {
    private class Runtime : AndroidFindBestControl.Runtime {
        var starts = 0; var recoveries = 0; var releases = 0
        override suspend fun start(selection: ProfileSelection) = Result.success(Unit).also { starts++ }
        override suspend fun stopCandidate() = Result.success(Unit)
        override suspend fun recover() = "RUNTIME_RESTORED".also { recoveries++ }
        override suspend fun release() = Result.success(Unit).also { releases++ }
    }
    private val captured = ControlCommitted("owner", 7L, PersistedState())
    private fun request() = ControlRequest("find", ControlCommand(ControlOperationId.FIND_BEST),
        controllerId = "owner", ifRevision = 7, asynchronous = true)

    @Test fun synchronousInteractiveSearchReturnsAcceptanceBeforeConsentCompletes() = runTest {
        val entered = CompletableDeferred<Unit>()
        val control = AndroidFindBestControl("owner", { captured }, { false }, { _, _, _, awaiting ->
            awaiting(true); entered.complete(Unit); awaitCancellation()
        }, { error("runtime") }, { error("plan") }, { _, _ -> error("probe") }, { error("verify") },
            { _, _, _, _ -> error("commit") }, {})
        val owner = AndroidSettingsControl("owner", backgroundScope, { captured }, { _, _, _ -> error("settings") },
            {}, { false }, findBest = { control })
        val waiting = backgroundScope.async { owner.execute(request().copy(asynchronous = false, interactive = true)) }
        entered.await(); runCurrent()
        assertTrue("The host needs acceptance before it can launch the consent token", waiting.isCompleted)
        assertEquals(ControlCode.ACCEPTED, waiting.await().code)
    }

    @Test fun cancellationIsCorrelatedWaitsForRecoveryAndPreservesPendingConfiguration() = runTest {
        val entered = CompletableDeferred<Unit>()
        val runtime = Runtime()
        var plans = 0; var commits = 0; var finished = 0
        val control = AndroidFindBestControl("owner", { captured }, { true }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { plans++; entered.complete(Unit); awaitCancellation() },
            { _, _ -> error("probe") }, { error("verify") }, { _, _, _, _ -> commits++; captured }, {}, {
                assertEquals(1, runtime.recoveries)
                assertEquals(1, runtime.releases)
                finished++
            })
        val jobs = AndroidCommandJobs(backgroundScope)
        val owner = AndroidSettingsControl("owner", backgroundScope, { captured }, { _, _, _ -> error("settings") },
            {}, { true }, mutationJobs = jobs, findBest = { control })
        val accepted = owner.execute(request())
        entered.await()
        assertTrue(owner.findBestActive.value)
        assertEquals(ControlCode.ACCEPTED, accepted.code)
        assertEquals(accepted.operationId, owner.execute(request()).operationId)
        assertEquals(ControlCode.BUSY, owner.execute(request().copy(requestId = "other")).code)
        val cancelled = owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(requireNotNull(accepted.operationId)))), controllerId = "owner"))
        assertEquals(ControlCode.OK, cancelled.code)
        val result = owner.execute(request())
        assertEquals(ControlCode.CANCELLED, result.code)
        assertTrue(result.restartRequired)
        assertEquals(7L, result.configurationRevision)
        assertEquals(1, plans); assertEquals(0, commits)
        assertEquals(1, runtime.recoveries); assertEquals(1, runtime.releases)
        assertEquals(1, finished)
        assertFalse(jobs.busy.value)
        assertFalse(owner.findBestActive.value)
    }

    @Test fun successfulVerificationCommitsOnceAndDoesNotRollback() = runTest {
        val runtime = Runtime()
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
        val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "private detail")
        val selection = ProfileSelection(profile, measured, "{}")
        val attempt = ProfileSelectionAttempt(selection, PreflightResult(profile, 1.0, "private"))
        val old = SubscriptionSource("source", "https://source.test", cachedLocations = emptyList())
        var persisted = captured.copy(value = captured.value.copy(subscriptions = listOf(old)))
        val caches = mapOf("source" to listOf(LocationConfigs.encodeStoredLocation(profile)))
        var verified = false
        var commits = 0
        var finished = 0
        val control = AndroidFindBestControl("owner", { persisted }, { false }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null), caches)) },
            { _, _ -> Result.success(measured) }, { assertEquals(old, persisted.value.subscriptions.single()); verified = true; Result.success(measured) },
            { winner, epoch, revision, prepared ->
                assertTrue(verified); assertEquals(caches, prepared.caches)
                assertEquals(measured.detail, prepared.candidates.locationBenchmarkDetails[LocationConfigs.encodeStoredLocation(profile)])
                assertEquals(selection, winner); assertEquals("owner", epoch); assertEquals(7L, revision)
                commits++
                persisted.copy(revision = 8, value = persisted.value.copy(subscriptions = prepared.subscriptions(persisted.value)))
                    .also { persisted = it }
            }, {}, {
                assertEquals("op", it)
                assertEquals(1, commits)
                assertEquals(1, runtime.releases)
                finished++
            })
        val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })
        assertEquals(ControlCode.OK, result.code)
        assertEquals(8L, result.configurationRevision)
        assertEquals(1, commits); assertEquals(1, runtime.starts)
        assertEquals(0, runtime.recoveries); assertEquals(1, runtime.releases)
        assertEquals(1, finished)
        assertEquals(caches.getValue("source"), persisted.value.subscriptions.single().cachedLocations)
        assertFalse(result.toString().contains("private"))
    }

    @Test fun deniedInteractionDoesNotPlanOrTouchRuntime() = runTest {
        var finished = 0
        val control = AndroidFindBestControl("owner", { captured }, { false }, { _, _, _, _ -> ControlCode.INTERACTION_REQUIRED },
            { error("runtime") }, { error("plan") }, { _, _ -> error("probe") }, { error("verify") },
            { _, _, _, _ -> error("commit") }, {}, { assertEquals("op", it); finished++ })
        assertEquals(ControlCode.INTERACTION_REQUIRED,
            control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true }).code)
        assertEquals(1, finished)
    }

    @Test fun interactionCleanupFailureDoesNotEraseKnownCommittedSuccess() = runTest {
        val runtime = Runtime()
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
        val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "measured")
        val attempt = ProfileSelectionAttempt(ProfileSelection(profile, measured, "{}"), PreflightResult(profile, 1.0, ""))
        val control = AndroidFindBestControl("owner", { captured }, { false }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
            { _, _ -> Result.success(measured) }, { Result.success(measured) },
            { _, _, _, _ -> captured.copy(revision = 8) }, {}, { throw OutOfMemoryError() })
        val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })
        assertEquals(ControlCode.OK, result.code)
        assertEquals(8L, result.configurationRevision)
        assertEquals(ControlValue.BooleanValue(true), result.data["committed"])
        assertTrue("INTERACTION_RELEASE_FAILED" in result.warnings)
        assertEquals(0, runtime.recoveries)
    }

    @Test fun failedPersistenceRecoversRuntimeWithoutOverwritingPendingSelection() = runTest {
        val runtime = Runtime()
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
        val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "private")
        val attempt = ProfileSelectionAttempt(ProfileSelection(profile, measured, "{}"), PreflightResult(profile, 1.0, ""))
        val control = AndroidFindBestControl("owner", { captured }, { true }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
            { _, _ -> Result.success(measured) }, { Result.success(measured) },
            { _, _, _, _ -> error("PRIVATE_STORAGE_FAILURE") }, {})
        val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(ControlValue.BooleanValue(false), result.data["committed"])
        assertTrue(result.restartRequired); assertEquals(7L, result.configurationRevision)
        assertEquals(listOf("RUNTIME_RESTORED"), result.warnings)
        assertEquals(1, runtime.recoveries); assertEquals(1, runtime.releases)
        assertFalse(result.toString().contains("PRIVATE"))
    }

    @Test fun failedPlanReportsOriginalFailureOnceWithoutChangingRecoveryOutcome() = runTest {
        val runtime = Runtime()
        val failure = IllegalStateException("PRIVATE_PLAN_FAILURE")
        val reported = mutableListOf<Throwable>()
        val control = AndroidFindBestControl("owner", { captured }, { true }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.failure(failure) }, { _, _ -> error("probe") }, { error("verify") },
            { _, _, _, _ -> error("commit") }, {}, reportFailure = { reported += it })

        val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })

        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(listOf("RUNTIME_RESTORED"), result.warnings)
        assertEquals(1, runtime.recoveries)
        assertEquals(1, runtime.releases)
        assertEquals(1, reported.size)
        assertTrue(reported.single().containsCauseIdentity(failure))
    }

    @Test fun swallowedProbeAndVerificationFailuresAreReportedBeforeExhaustion() = runTest {
        for (stage in listOf("probe", "verify")) {
            val runtime = Runtime()
            val failure = IllegalStateException("PRIVATE_$stage")
            val reported = mutableListOf<Throwable>()
            val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
            val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "")
            val attempt = ProfileSelectionAttempt(ProfileSelection(profile, measured, "{}"), PreflightResult(profile, 1.0, ""))
            val control = AndroidFindBestControl("owner", { captured }, { false }, { _, _, _, _ -> ControlCode.OK },
                { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
                { _, _ -> if (stage == "probe") Result.failure(failure) else Result.success(measured) },
                { if (stage == "verify") Result.failure(failure) else Result.success(measured) },
                { _, _, _, _ -> error("commit") }, {}, reportFailure = { reported += it })

            val result = control.execute(request(), "op-$stage", { _, _ -> }, { true }, { true }, { true })

            assertEquals(ControlCode.RUNTIME_FAILED, result.code)
            assertEquals(1, runtime.recoveries)
            assertEquals(1, runtime.releases)
            assertEquals(1, reported.count { it === failure })
            assertEquals(1, reported.count { it is AndroidFindBestNoVerifiedCandidateException })
        }
    }

    @Test fun nativeStartCancellationWaitsForAckBeforeRecovery() = runTest {
        val entered = CompletableDeferred<Unit>(); val ack = CompletableDeferred<Unit>()
        var recovered = false
        val runtime = object : AndroidFindBestControl.Runtime {
            override suspend fun start(selection: ProfileSelection): Result<Unit> { entered.complete(Unit); ack.await(); return Result.success(Unit) }
            override suspend fun stopCandidate() = Result.success(Unit)
            override suspend fun recover() = "RUNTIME_RESTORED".also { recovered = true }
            override suspend fun release() = Result.success(Unit)
        }
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
        val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "")
        val attempt = ProfileSelectionAttempt(ProfileSelection(profile, measured, "{}"), PreflightResult(profile, 1.0, ""))
        val control = AndroidFindBestControl("owner", { captured }, { true }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
            { _, _ -> Result.success(measured) }, { error("cancelled before verification") }, { _, _, _, _ -> error("commit") }, {})
        val result = async { control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true }) }
        entered.await(); control.cancel("op"); runCurrent()
        assertFalse(result.isCompleted); assertFalse(recovered)
        ack.complete(Unit)
        assertEquals(ControlCode.CANCELLED, result.await().code); assertTrue(recovered)
    }

    @Test fun commitResponseLossReconcilesExactSelectionAndUnknownReadNeverRollsBack() = runTest {
        for (readable in listOf(true, false)) for (failure in listOf(
            java.io.IOException("result unavailable"), CancellationException("result cancelled"),
            OutOfMemoryError("result allocation failed"),
        )) {
            val runtime = Runtime()
            val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
            val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "")
            val selection = ProfileSelection(profile, measured, "{}")
            val attempt = ProfileSelectionAttempt(selection, PreflightResult(profile, 1.0, ""))
            var committed = false
            val control = AndroidFindBestControl("owner", {
                if (!committed) captured else {
                    if (!readable) throw java.io.IOException("read unavailable")
                    captured.copy(revision = 8, value = captured.value.copy(
                        selectedProfileName = profile.remarks, selectedProfileServer = profile.server,
                        selectedProfileJson = LocationConfigs.encodeStoredLocation(profile),
                        selectedProfileRawLink = profile.rawLink, runtimeConfigJson = "{}",
                        lastBenchmarkSummary = measured.detail,
                        locationBenchmarkDetails = mapOf(LocationConfigs.encodeStoredLocation(profile) to measured.detail)))
                }
            }, { false }, { _, _, _, _ -> ControlCode.OK }, { runtime },
                { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
                { _, _ -> Result.success(measured) }, { Result.success(measured) },
                { _, _, _, _ -> committed = true; throw failure }, {})
            val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })
            assertEquals("Never restore old runtime after an uncertain durable commit", 0, runtime.recoveries)
            assertEquals(1, runtime.releases)
            if (readable) {
                assertEquals(ControlCode.OK, result.code)
                assertEquals(8L, result.configurationRevision)
                assertEquals(ControlValue.BooleanValue(true), result.data["committed"])
            } else {
                assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
                assertEquals(ControlValue.Null, result.data["committed"])
                assertTrue(result.warnings.contains("CONFIGURATION_OUTCOME_UNKNOWN"))
            }
        }
    }

    @Test fun failedCommitOfAlreadySelectedWinnerDoesNotInventPersistedMeasurements() = runTest {
        val runtime = Runtime()
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#winner")
        val raw = LocationConfigs.encodeStoredLocation(profile)
        val measured = ProfileBenchmark(profile, "ok", "ok", 1.0, 2.0, 1.0, "new measurement")
        val selection = ProfileSelection(profile, measured, "{}")
        val attempt = ProfileSelectionAttempt(selection, PreflightResult(profile, 1.0, ""))
        val before = captured.copy(value = captured.value.copy(selectedProfileName = profile.remarks,
            selectedProfileServer = profile.server, selectedProfileJson = raw,
            selectedProfileRawLink = profile.rawLink, runtimeConfigJson = "{}",
            lastBenchmarkSummary = "previous measurement", locationBenchmarkDetails = mapOf(raw to "previous measurement")))
        val control = AndroidFindBestControl("owner", { before }, { false }, { _, _, _, _ -> ControlCode.OK },
            { runtime }, { Result.success(AndroidFindBestPlan(ProfileSelectionAttemptPlan(listOf(attempt), emptyMap(), null))) },
            { _, _ -> Result.success(measured) }, { Result.success(measured) },
            { _, _, _, _ -> throw java.io.IOException("No metadata was committed") }, {})
        val result = control.execute(request(), "op", { _, _ -> }, { true }, { true }, { true })
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(ControlValue.BooleanValue(false), result.data["committed"])
        assertEquals(1, runtime.recoveries)
        assertEquals(1, runtime.releases)
    }

    private fun Throwable.containsCauseIdentity(target: Throwable): Boolean {
        val seen = java.util.IdentityHashMap<Throwable, Unit>()
        var current: Throwable? = this
        while (current != null && seen.put(current, Unit) == null) {
            if (current === target) return true
            current = current.cause
        }
        return false
    }

    @Test fun publicFindBestReachesAuthoritativeOwnerWithoutFrontend() = runTest {
        var calls = 0
        val reader = AndroidControlReader("owner", { PersistedState() }, settingsWrite = { request ->
            calls++
            assertEquals(ControlOperationId.FIND_BEST, request.command.operation)
            assertEquals("owner", request.controllerId)
            assertEquals(7L, request.ifRevision)
            ControlResult(controllerId = "owner", requestId = request.requestId,
                operationId = "find-best-operation", code = ControlCode.ACCEPTED, final = false,
                configurationRevision = 7)
        })
        val request = ControlRequest("find-best", ControlCommand(ControlOperationId.FIND_BEST),
            controllerId = "owner", ifRevision = 7, asynchronous = true)
        val result = reader.read(request)
        assertEquals(ControlCode.ACCEPTED, result.code)
        assertEquals("find-best-operation", result.operationId)
        assertEquals(1, calls)
    }
}
