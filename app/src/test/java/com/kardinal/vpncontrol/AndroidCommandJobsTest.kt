package com.kardinal.vpncontrol

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidCommandJobsTest {
    @Test fun closedTrackedScopeDoesNotLeakLease() = runTest {
        val closed = CoroutineScope(SupervisorJob()).apply { cancel() }
        val commands = AndroidCommandJobs(closed)
        assertNotNull(commands.launchTracked { fail("closed owner") })
        assertFalse(commands.busy.value)
        val lease = commands.tryAcquireMutation()
        assertNotNull(lease)
        commands.releaseMutation(requireNotNull(lease))
    }

    @Test fun serviceAcknowledgmentCompletesWhileCallerHoldsMutationLease() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        val receipts = AndroidRuntimeCommands()
        val ticket = receipts.register(AndroidRuntimeAction.STOP)
        var completed = false
        commands.launchTracked { receipts.await(ticket, 1000).getOrThrow(); completed = true }
        runCurrent()
        assertTrue(commands.busy.value)
        assertTrue(receipts.claim(ticket.id, AndroidRuntimeAction.STOP))
        receipts.complete(ticket.id, Result.success(Unit))
        runCurrent()
        assertTrue(completed)
        assertFalse(commands.busy.value)
    }
    @Test
    fun destroyingFrontendDoesNotCancelWorkAndReplacementObservesBusy() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        val release = CompletableDeferred<Unit>()
        var completed = false
        val frontend = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        frontend.launch { commands.busy.collect() }
        val work = commands.launchTracked { release.await(); completed = true }!!
        runCurrent()
        frontend.cancel()

        assertTrue(work.isActive)
        assertTrue(commands.busy.value)
        assertNull(commands.launchTracked { fail("Second frontend must not start a competing operation") })
        release.complete(Unit)
        runCurrent()
        assertTrue(completed)
        assertFalse(commands.busy.value)
        assertNotNull(commands.launchTracked {})
    }

    @Test
    fun cancellationKeepsAdmissionClosedUntilRollbackFinishes() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        val cleanup = CompletableDeferred<Unit>()
        commands.launchTracked {
            try {
                CompletableDeferred<Unit>().await()
            } finally {
                withContext(NonCancellable) { cleanup.await() }
            }
        }
        runCurrent()
        commands.cancelActive()
        runCurrent()
        commands.setBusy(false)
        assertTrue(commands.busy.value)
        assertNull(commands.launchTracked {})
        cleanup.complete(Unit)
        runCurrent()
        assertFalse(commands.busy.value)
        assertNotNull(commands.launchTracked {})
    }

    @Test
    fun cancelledWorkerWaitDoesNotCancelItsOwnerOperation() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        val release = CompletableDeferred<Unit>()
        var completed = false
        val waiter = launch {
            commands.runTracked { release.await(); completed = true; Unit }
        }
        runCurrent()
        waiter.cancel()
        runCurrent()
        assertTrue(commands.busy.value)
        assertNull(commands.runTracked { Unit })
        release.complete(Unit)
        runCurrent()
        assertTrue(completed)
        assertFalse(commands.busy.value)
    }

    @Test
    fun immediatelyCompletedCommandDoesNotLeaveStaleAdmission() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        repeat(3) {
            assertNotNull(commands.launchTracked {})
            runCurrent()
            assertFalse(commands.busy.value)
        }
    }

    @Test
    fun workerFailureReturnsToWaiterWithoutCrashingOwnerScope() = runTest {
        val commands = AndroidCommandJobs(backgroundScope)
        var failure: Throwable? = null
        val waiter = launch {
            try {
                commands.runTracked<Unit> { throw IllegalStateException("fixture failure") }
            } catch (error: Throwable) {
                failure = error
            }
        }
        runCurrent()
        waiter.join()
        assertEquals("fixture failure", failure?.message)
        assertFalse(commands.busy.value)
        assertNotNull(commands.launchTracked {})
    }
}
