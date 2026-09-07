package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopInstallHandoffTest {
    @Test fun confirmedCancellationStillPropagatesInterruptionAndClosesWorker() = runBlocking {
        val events = mutableListOf<String>()
        val handoff = DesktopInstallHandoff(prepare = { Result.success(worker(events)) },
            stopRuntime = { throw kotlinx.coroutines.CancellationException() },
            requestExit = { fail("Must not exit") })
        assertFailsWith<kotlinx.coroutines.CancellationException> { handoff.prepare("request") }
        assertEquals(listOf("cancel", "close"), events)
        assertEquals(ControlCode.NOT_FOUND, handoff.retryCancellation().code)
        handoff.close()
    }

    @Test fun interruptedCommitDoesNotClaimCancellationWithoutWorkerAcknowledgment() = runBlocking {
        var confirmed = false
        var closed = 0
        val prepared = object : DesktopPreparedInstall {
            override val jobId = "00000000-0000-0000-0000-000000000001"
            override suspend fun commit(): Result<Unit> = throw kotlinx.coroutines.CancellationException()
            override fun cancel() = if (confirmed) Result.success(Unit)
                else Result.failure(IllegalStateException("UNAVAILABLE"))
            override fun close() { closed++ }
        }
        val handoff = DesktopInstallHandoff(prepare = { Result.success(prepared) },
            stopRuntime = { Result.success(Unit) }, requestExit = { fail("Must not exit") })
        val result = handoff.prepare("request")
        assertEquals(DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, prepared.jobId), result)
        assertEquals(0, closed)
        assertEquals(ControlCode.BUSY, handoff.prepare("another").code)
        confirmed = true
        assertEquals(DesktopInstallHandoffResult(ControlCode.CANCELLED, prepared.jobId), handoff.retryCancellation())
        assertEquals(1, closed)
        handoff.close()
    }

    @Test fun thrownPreparationUncertaintyAlsoRetainsWorkerAndCorrelation() = runBlocking {
        val prepared = object : DesktopPreparedInstall {
            override val jobId = "00000000-0000-0000-0000-000000000001"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel() = Result.failure<Unit>(IllegalStateException("UNAVAILABLE"))
            override fun close() {}
        }
        val handoff = DesktopInstallHandoff(
            prepare = { throw DesktopInstallPreparationFailure(prepared, IllegalStateException("OUTCOME_UNKNOWN")) },
            stopRuntime = { fail("Uncertain preparation must not stop runtime") }, requestExit = { fail("Must not exit") })
        assertEquals(DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, prepared.jobId), handoff.prepare("request"))
        assertEquals(ControlCode.BUSY, handoff.prepare("retry").code)
        handoff.close()
    }
    @Test fun workerCreatedBeforeReadinessFailureRetainsItsIdentityUntilCancellationConfirmed() = runBlocking {
        val events = mutableListOf<String>()
        val created = object : DesktopPreparedInstall {
            override val jobId = "00000000-0000-0000-0000-000000000001"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel(): Result<Unit> { events += "cancel"; return Result.failure(IllegalStateException("UNAVAILABLE")) }
            override fun close() { events += "close" }
        }
        val handoff = DesktopInstallHandoff(
            prepare = { Result.failure(DesktopInstallPreparationFailure(created, IllegalStateException("TIMEOUT"))) },
            stopRuntime = { fail("Readiness failure must not stop runtime") }, requestExit = { fail("Must not exit") })
        assertEquals(DesktopInstallHandoffResult(ControlCode.OUTCOME_UNKNOWN, created.jobId), handoff.prepare("first"))
        assertEquals(ControlCode.BUSY, handoff.prepare("second").code)
        assertEquals(listOf("cancel"), events)
        handoff.close()
        assertEquals(listOf("cancel", "close"), events)
    }
    @Test fun authorizationFailureNeverStopsRuntimeOrRequestsExit() = runBlocking {
        val events = mutableListOf<String>()
        val result = DesktopInstallHandoff(
            prepare = { events += "authorize"; Result.failure(IllegalStateException("CANCELLED")) },
            stopRuntime = { events += "stop"; Result.success(Unit) },
            requestExit = { events += "exit:$it" },
        ).prepare("request")
        assertEquals(ControlCode.CANCELLED, result.code)
        assertEquals(listOf("authorize"), events)
    }

    @Test fun failedStopCancelsProtectedWorkerWithoutExit() = runBlocking {
        val events = mutableListOf<String>()
        val worker = worker(events)
        val result = DesktopInstallHandoff(
            prepare = { events += "authorize"; Result.success(worker) },
            stopRuntime = { events += "stop"; Result.failure(IllegalStateException("RUNTIME_FAILED")) },
            requestExit = { events += "exit:$it" },
        ).prepare("request")
        assertEquals(ControlCode.RUNTIME_FAILED, result.code)
        assertEquals(listOf("authorize", "stop", "cancel", "close"), events)
    }

    @Test fun exactResponseExitIsArmedOnlyAfterProtectedWorkerCommit() = runBlocking {
        val events = mutableListOf<String>()
        val handoff = DesktopInstallHandoff(
            prepare = { events += "authorize"; Result.success(worker(events)) },
            stopRuntime = { events += "stop"; Result.success(Unit) },
            requestExit = { events += "exit:$it" },
        )
        val result = handoff.prepare("request")
        assertEquals(ControlCode.OK, result.code)
        assertEquals("00000000-0000-0000-0000-000000000001", result.jobId)
        assertEquals(listOf("authorize", "stop", "commit", "exit:request"), events)
        assertEquals(ControlCode.BUSY, handoff.prepare("another").code)
        assertEquals(ControlCode.BUSY, handoff.retryCancellation().code)
        handoff.close()
        handoff.close()
        assertEquals("close", events.last())
        assertFalse("cancel" in events)
    }

    @Test fun unconfirmedCancellationPreventsAnotherInstallerAdmission() = runBlocking {
        val events = mutableListOf<String>()
        val handoff = DesktopInstallHandoff(
            prepare = { Result.success(object : DesktopPreparedInstall {
                override val jobId = "00000000-0000-0000-0000-000000000001"
                override suspend fun commit() = Result.success(Unit)
                override fun cancel(): Result<Unit> {
                    events += "cancel"
                    return Result.failure(IllegalStateException("UNAVAILABLE"))
                }
                override fun close() { events += "close" }
            }) },
            stopRuntime = { Result.failure(IllegalStateException("RUNTIME_FAILED")) },
            requestExit = { fail("Must not request exit") },
        )
        val unknown = handoff.prepare("first")
        assertEquals(ControlCode.OUTCOME_UNKNOWN, unknown.code)
        assertEquals("00000000-0000-0000-0000-000000000001", unknown.jobId)
        assertEquals(ControlCode.BUSY, handoff.prepare("second").code)
        assertEquals(unknown, handoff.retryCancellation())
        assertEquals(listOf("cancel", "cancel"), events)
        handoff.close()
        handoff.close()
        assertEquals(unknown, handoff.retryCancellation())
        assertEquals(listOf("cancel", "cancel", "close"), events)
    }

    @Test fun failedCancellationRetainsWorkerUntilExplicitSuccessfulRetry() = runBlocking {
        val events = mutableListOf<String>()
        var attempts = 0
        val handoff = DesktopInstallHandoff(
            prepare = { events += "authorize"; Result.success(object : DesktopPreparedInstall {
                override val jobId = "00000000-0000-0000-0000-000000000001"
                override suspend fun commit() = Result.success(Unit)
                override fun cancel(): Result<Unit> {
                    events += "cancel"
                    return if (++attempts == 1) Result.failure(IllegalStateException("UNAVAILABLE")) else Result.success(Unit)
                }
                override fun close() { events += "close" }
            }) },
            stopRuntime = { Result.failure(IllegalStateException("RUNTIME_FAILED")) },
            requestExit = { fail("Must not request exit") },
        )
        val first = handoff.prepare("first")
        assertEquals(ControlCode.OUTCOME_UNKNOWN, first.code)
        assertEquals(ControlCode.BUSY, handoff.prepare("second").code)
        assertEquals(DesktopInstallHandoffResult(ControlCode.CANCELLED, first.jobId), handoff.retryCancellation())
        handoff.close()
        handoff.close()
        assertEquals(listOf("authorize", "cancel", "cancel", "close"), events)
    }

    private fun worker(events: MutableList<String>) = object : DesktopPreparedInstall {
        override val jobId = "00000000-0000-0000-0000-000000000001"
        override suspend fun commit(): Result<Unit> { events += "commit"; return Result.success(Unit) }
        override fun cancel(): Result<Unit> { events += "cancel"; return Result.success(Unit) }
        override fun close() { events += "close" }
    }
}
