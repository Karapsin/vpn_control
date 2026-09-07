package com.kardinal.vpncontrol

import org.junit.Test
import org.junit.Assert.*

class AndroidInstallSessionLifecycleTest {
    @Test fun stagingJournalPrecedesCreationAndCannotCommitIncompleteBytes() {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val lifecycle = AndroidInstallSessionLifecycle(receipt().copy(sessionId = -1,
            phase = AndroidInstallSessionPhase.PREPARING), writes::add)
        assertThrows(IllegalStateException::class.java) { lifecycle.beforeCommit() }
        lifecycle.sessionCreated(18)
        assertEquals(18, writes.last().sessionId)
        assertTrue(lifecycle.canAbandon())
        lifecycle.staged()
        lifecycle.beforeCommit()
        assertFalse(lifecycle.canAbandon())
    }

    @Test fun preparingAndReconciliationArePublishedOnlyAfterDurableTransitions() {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val published = mutableListOf<AndroidInstallSessionReceipt>()
        var reject = false
        val lifecycle = AndroidInstallSessionLifecycle(receipt().copy(sessionId = -1,
            phase = AndroidInstallSessionPhase.PREPARING), { value ->
            if (reject) error("Persistence failed")
            writes += value
        }) { value ->
            assertEquals(value, writes.last())
            published += value
        }
        lifecycle.sessionCreated(18)
        lifecycle.staged()
        reject = true
        assertThrows(IllegalStateException::class.java) { lifecycle.beforeCommit() }
        assertEquals(listOf(AndroidInstallSessionPhase.PREPARING, AndroidInstallSessionPhase.STAGED), published.map { it.phase })
        reject = false
        lifecycle.beforeCommit()
        lifecycle.reconcile(false)
        assertEquals(AndroidInstallSessionPhase.UNKNOWN, published.last().phase)
        assertEquals(writes, published)
    }
    private fun receipt() = AndroidInstallSessionReceipt(
        id = "receipt", nonce = "nonce", sessionId = 17, version = "2.3.4",
        build = 123, sha256 = "a".repeat(64), byteCount = 100,
        phase = AndroidInstallSessionPhase.STAGED,
    )

    @Test fun exactCallbackIsRequiredAndHandoffIsNotInstallation() {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val lifecycle = AndroidInstallSessionLifecycle(receipt(), writes::add)
        lifecycle.beforeCommit()
        assertFalse(lifecycle.callback(18, "nonce", AndroidInstallSessionPhase.INSTALLED))
        assertFalse(lifecycle.callback(17, "other", AndroidInstallSessionPhase.INSTALLED))
        assertEquals(AndroidInstallSessionPhase.COMMITTING, lifecycle.snapshot().phase)
        assertTrue(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.AWAITING_CONFIRMATION))
        lifecycle.handedOff()
        assertEquals(AndroidInstallSessionPhase.HANDED_OFF, lifecycle.snapshot().phase)
        assertFalse(lifecycle.snapshot().terminal)
        assertTrue(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.INSTALLED))
        assertTrue(lifecycle.snapshot().terminal)
        assertFalse(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.FAILED))
        assertEquals(AndroidInstallSessionPhase.INSTALLED, writes.last().phase)
    }

    @Test fun MissingSessionAndNewInstalledVersionDoNotProveSuccess() {
        val lifecycle = AndroidInstallSessionLifecycle(receipt().copy(
            phase = AndroidInstallSessionPhase.HANDED_OFF), {})
        lifecycle.reconcile(sessionPresent = false)
        assertEquals(AndroidInstallSessionPhase.UNKNOWN, lifecycle.snapshot().phase)
        assertFalse(lifecycle.snapshot().terminal)
        assertFalse(lifecycle.canAbandon())
        // A late exact OS receipt can still resolve the unknown outcome.
        assertTrue(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.INSTALLED))
    }

    @Test fun explicitConfirmationResumeDoesNotDemoteOrRewriteAcknowledgedHandoff() {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val before = receipt().copy(phase = AndroidInstallSessionPhase.HANDED_OFF,
            confirmation = "immutable-confirmation-capability")
        val lifecycle = AndroidInstallSessionLifecycle(before, writes::add)
        lifecycle.handedOff()
        assertEquals(before, lifecycle.snapshot())
        assertTrue(writes.isEmpty())
    }

    @Test fun exactCancellationReceiptIsTerminalAndCannotBeReplacedByLateSuccess() {
        val writes = mutableListOf<AndroidInstallSessionReceipt>()
        val lifecycle = AndroidInstallSessionLifecycle(receipt(), writes::add)
        lifecycle.beforeCommit()
        assertTrue(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.CANCELLED))
        assertTrue(lifecycle.snapshot().terminal)
        assertFalse(lifecycle.canAbandon())
        assertFalse(lifecycle.callback(17, "nonce", AndroidInstallSessionPhase.INSTALLED))
        assertEquals(AndroidInstallSessionPhase.CANCELLED, writes.last().phase)
    }

    @Test fun CancellationOnlyAbandonsBeforeCommitAndFailedPersistencePreventsCommit() {
        val lifecycle = AndroidInstallSessionLifecycle(receipt(), {})
        assertTrue(lifecycle.canAbandon())
        lifecycle.beforeCommit()
        assertFalse(lifecycle.canAbandon())
        val failing = AndroidInstallSessionLifecycle(receipt()) { error("disk unavailable") }
        assertThrows(IllegalStateException::class.java) { failing.beforeCommit() }
        assertEquals(AndroidInstallSessionPhase.STAGED, failing.snapshot().phase)
        assertTrue(failing.canAbandon())
    }
}
