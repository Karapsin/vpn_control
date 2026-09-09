package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopOperationRetainedInputsTest {
    @Test
    fun failedRestoreActionCloseRemainsRetryableUntilItsInputsAreReleased() {
        var closes = 0
        val action = DesktopRuntimeRestoreAction(AutoCloseable {
            closes++
            if (closes == 1) throw IOException("fixture release failure")
        }) { Result.success(Unit) }

        assertFailsWith<IOException> { action.close() }
        action.close()
        action.close()

        assertEquals(2, closes, "A failed release must retain its exact cleanup owner for retry")
    }

    @Test
    fun nativeConfirmationKeepsExactRecoveryUntilItsOwnerMakesTheTerminalDecision() {
        val observations = mutableListOf<ControlCode?>()
        val progress = DesktopOperationProgress(observations::add)
        var closes = 0
        var restores = 0
        val action = DesktopRuntimeRestoreAction(AutoCloseable { closes++ }) {
            restores++
            Result.success(Unit)
        }
        progress.retainInputs(action)

        progress.pending(ControlCode.OUTCOME_UNKNOWN)
        assertTrue(progress.hasPendingOutcome)
        assertEquals("OUTCOME_UNKNOWN", progress.releaseInputs(action).exceptionOrNull()?.message)
        assertEquals("OUTCOME_UNKNOWN", progress.releaseAllTerminal().exceptionOrNull()?.message)
        assertTrue(progress.hasRetainedInputs)
        assertEquals(0, closes)

        progress.confirmed()
        assertFalse(progress.hasPendingOutcome)
        assertTrue(progress.hasRetainedInputs)
        assertEquals(0, closes, "Native evidence does not settle the enclosing recovery decision")
        assertEquals(0, restores, "Confirmation must never replay a runtime action")

        progress.releaseInputs(action).getOrThrow()
        progress.releaseInputs(action).getOrThrow()
        progress.releaseAllTerminal().getOrThrow()
        assertFalse(progress.hasRetainedInputs)
        assertEquals(1, closes)
        assertEquals(0, restores)
        assertEquals(listOf(ControlCode.OUTCOME_UNKNOWN, null), observations)
    }

    @Test
    fun knownOutcomeKeepsOnlyFailedCleanupForExplicitRetryWithoutBecomingUnknown() {
        val observations = mutableListOf<ControlCode?>()
        val progress = DesktopOperationProgress(observations::add)
        var completedCloses = 0
        var retryCloses = 0
        val completed = AutoCloseable { completedCloses++ }
        val retry = DesktopRuntimeRestoreAction(AutoCloseable {
            retryCloses++
            if (retryCloses == 1) throw IOException("fixture release failure")
        }) { error("Cleanup must never replay recovery") }
        progress.retainInputs(completed)
        progress.retainInputs(retry)
        progress.pending(ControlCode.OUTCOME_UNKNOWN)
        progress.confirmed()

        assertTrue(progress.releaseAllTerminal().isFailure)
        assertTrue(progress.hasRetainedInputs)
        assertFalse(progress.hasPendingOutcome)
        assertEquals(listOf(ControlCode.OUTCOME_UNKNOWN, null), observations)
        assertEquals(1, completedCloses)
        assertEquals(1, retryCloses)

        progress.releaseAllTerminal().getOrThrow()
        progress.releaseAllTerminal().getOrThrow()
        assertFalse(progress.hasRetainedInputs)
        assertFalse(progress.hasPendingOutcome)
        assertEquals(1, completedCloses)
        assertEquals(2, retryCloses)
        assertEquals(listOf(ControlCode.OUTCOME_UNKNOWN, null), observations)
    }

    @Test
    fun equalOwnersRemainDistinctAndRepeatedRegistrationDoesNotDuplicateRelease() {
        val first = EqualCleanupOwner()
        val second = EqualCleanupOwner()
        assertEquals(first, second)
        val inputs = DesktopOperationRetainedInputs()
        inputs.retain(first)
        inputs.retain(second)
        inputs.retain(first)

        inputs.release(first).getOrThrow()
        assertTrue(inputs.hasRetainedInputs)
        assertEquals(0, second.closes)
        inputs.releaseAllTerminal().getOrThrow()
        inputs.releaseAllTerminal().getOrThrow()
        assertFalse(inputs.hasRetainedInputs)
        assertEquals(1, first.closes)
        assertEquals(1, second.closes)
    }

    @Test
    fun anotherOperationCannotReleaseInputsAndTerminalOwnerCannotAcceptNewInputs() {
        var closes = 0
        val action = AutoCloseable { closes++ }
        val owner = DesktopOperationProgress {}
        val other = DesktopOperationProgress {}
        owner.retainInputs(action)

        assertEquals("CONFLICT", other.releaseInputs(action).exceptionOrNull()?.message)
        assertTrue(owner.hasRetainedInputs)
        assertEquals(0, closes)
        owner.releaseAllTerminal().getOrThrow()
        assertFailsWith<IllegalStateException> { owner.retainInputs(AutoCloseable {}) }
        assertEquals(1, closes)
    }

    @Test
    fun concurrentReleaseKeepsOneExactCleanupAttemptInFlight() {
        val inputs = DesktopOperationRetainedInputs()
        val entered = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        var closes = 0
        val action = AutoCloseable {
            closes++
            entered.countDown()
            check(finish.await(5, TimeUnit.SECONDS))
        }
        inputs.retain(action)
        try {
            val first = executor.submit<Result<Unit>> { inputs.release(action) }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(inputs.hasRetainedInputs)
            assertEquals("UNAVAILABLE", inputs.release(action).exceptionOrNull()?.message)
            finish.countDown()
            first.get(5, TimeUnit.SECONDS).getOrThrow()
            inputs.releaseAllTerminal().getOrThrow()
            assertFalse(inputs.hasRetainedInputs)
            assertEquals(1, closes)
        } finally {
            finish.countDown()
            executor.shutdown()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }
}

private class EqualCleanupOwner : AutoCloseable {
    var closes = 0
    override fun close() { closes++ }
    override fun equals(other: Any?) = other is EqualCleanupOwner
    override fun hashCode() = 1
}
