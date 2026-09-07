package com.kardinal.vpncontrol

import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidInstallConfirmationRecoveryTest {
    @Test fun processLossRefreshesOnlyTheExactExistingSessionAndWaitsForItsNewCapability() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.HANDED_OFF)
        val work = async { f.recovery.prepare() }
        runCurrent()
        assertEquals(listOf(17), f.validated)
        assertEquals(listOf(17), f.committed)
        assertFalse(work.isCompleted)
        assertEquals(AndroidInstallSessionPhase.HANDED_OFF, f.lifecycle.snapshot().phase)
        assertFalse(f.callback(18, "nonce", AndroidInstallSessionPhase.AWAITING_CONFIRMATION))
        assertFalse(f.callback(17, "foreign", AndroidInstallSessionPhase.INSTALLED))
        runCurrent()
        assertFalse(work.isCompleted)
        assertTrue(f.callback(17, "nonce", AndroidInstallSessionPhase.AWAITING_CONFIRMATION))
        assertSame(f.capability, work.await())
        assertEquals(AndroidInstallSessionPhase.HANDED_OFF, f.lifecycle.snapshot().phase)
        assertEquals(listOf(17), f.committed)
    }

    @Test fun retainedConfirmationDoesNotRecommitAndConstructionDoesNotStartRecovery() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.HANDED_OFF)
        assertTrue(f.validated.isEmpty())
        assertTrue(f.committed.isEmpty())
        f.capability = Any()
        assertSame(f.capability, f.recovery.prepare())
        assertTrue(f.committed.isEmpty())
    }

    @Test fun freshSessionPersistsCommitBeforeCallingAndroid() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.STAGED)
        val work = async { f.recovery.prepare() }
        runCurrent()
        assertEquals(listOf(AndroidInstallSessionPhase.COMMITTING), f.writes.map { it.phase })
        assertEquals(listOf(17), f.committed)
        assertFalse(work.isCompleted)
        f.callback(17, "nonce", AndroidInstallSessionPhase.AWAITING_CONFIRMATION)
        assertSame(f.capability, work.await())
    }

    @Test fun processLossBeforePendingCallbackResumesTheSameCommittingSession() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.COMMITTING)
        val work = async { f.recovery.prepare() }
        runCurrent()
        assertEquals(listOf(17), f.committed)
        assertTrue(f.writes.isEmpty())
        assertFalse(work.isCompleted)
        f.callback(17, "nonce", AndroidInstallSessionPhase.AWAITING_CONFIRMATION)
        assertSame(f.capability, work.await())
    }

    @Test fun foreignOrMissingSessionCannotBeCommittedOrLaunched() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.HANDED_OFF)
        f.sessionValid = false
        assertTrue(runCatching { f.recovery.prepare() }.isFailure)
        assertTrue(f.committed.isEmpty())
        assertTrue(f.writes.isEmpty())
        assertEquals(AndroidInstallSessionPhase.HANDED_OFF, f.lifecycle.snapshot().phase)
    }

    @Test fun terminalCallbackWinsWhileReplacementConfirmationIsPending() = runTest {
        for (phase in listOf(AndroidInstallSessionPhase.INSTALLED, AndroidInstallSessionPhase.CANCELLED,
            AndroidInstallSessionPhase.FAILED)) {
            val f = Fixture(AndroidInstallSessionPhase.HANDED_OFF)
            val work = async { runCatching { f.recovery.prepare() } }
            runCurrent()
            f.callback(17, "nonce", phase)
            assertTrue(work.await().isFailure)
            assertEquals(phase, f.lifecycle.snapshot().phase)
            assertEquals(listOf(17), f.committed)
            assertNull(f.capability)
        }
    }

    @Test fun callbackLossDoesNotCreateAnotherSessionOrRewritePreviousHandoff() = runTest {
        val f = Fixture(AndroidInstallSessionPhase.HANDED_OFF)
        assertTrue(runCatching { withTimeout(100) { f.recovery.prepare() } }.isFailure)
        assertEquals(listOf(17), f.committed)
        assertTrue(f.writes.isEmpty())
        assertEquals(AndroidInstallSessionPhase.HANDED_OFF, f.lifecycle.snapshot().phase)
        assertFalse(f.lifecycle.canAbandon())
    }

    @Test fun unknownAndTerminalReceiptsCannotTriggerACommit() = runTest {
        for (phase in listOf(AndroidInstallSessionPhase.UNKNOWN, AndroidInstallSessionPhase.INSTALLED,
            AndroidInstallSessionPhase.CANCELLED, AndroidInstallSessionPhase.FAILED)) {
            val f = Fixture(phase)
            assertTrue(runCatching { f.recovery.prepare() }.isFailure)
            assertTrue(f.validated.isEmpty())
            assertTrue(f.committed.isEmpty())
        }
    }

    private class Fixture(phase: AndroidInstallSessionPhase) {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val lifecycle = AndroidInstallSessionLifecycle(AndroidInstallSessionReceipt(
            "receipt", "nonce", 17, "2.1.4", 16480, "a".repeat(64), 100, phase,
            confirmation = if (phase == AndroidInstallSessionPhase.STAGED) null else "filter"), writes::add)
        var capability: Any? = null
        var sessionValid = true
        val validated = mutableListOf<Int>()
        val committed = mutableListOf<Int>()
        val changed = MutableStateFlow(0)
        val recovery = AndroidInstallConfirmationRecovery(lifecycle, { capability }, {
            validated += it.sessionId
            check(sessionValid)
        }, {
            assertEquals(it.id, lifecycle.snapshot().id)
            assertEquals(it.sessionId, lifecycle.snapshot().sessionId)
            assertFalse(lifecycle.canAbandon())
            committed += it.sessionId
        }, { predicate -> changed.first { predicate() } })

        fun callback(session: Int, nonce: String, phase: AndroidInstallSessionPhase): Boolean {
            val accepted = lifecycle.callback(session, nonce, phase, "filter")
            if (accepted && phase == AndroidInstallSessionPhase.AWAITING_CONFIRMATION) capability = Any()
            changed.value++
            return accepted
        }
    }
}
