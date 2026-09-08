package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*

class DesktopWindowsScopedRuntimeProcessTest {
    private class Channel : DesktopWindowsPreparedRuntimeChannel {
        override val childPid = 41L
        var alive = true
        var lost = false
        var childDead = false
        var closed = false
        var commits = 0
        var aborts = 0
        var failCommit = false
        var failClose = false
        var abortConfirmed = true
        var reconciliation: DesktopWindowsNativeResourceReconciliation? = null
        val stops = mutableListOf<Boolean>()
        override fun status(): DesktopWindowsRuntimeStatus {
            check(!lost) { "OUTCOME_UNKNOWN" }
            return DesktopWindowsRuntimeStatus(alive, resourceReconciliation = reconciliation)
        }
        override fun stop(force: Boolean) { stops += force; check(!lost) { "OUTCOME_UNKNOWN" } }
        override fun childExited() = childDead
        override fun close() { check(!failClose) { "OUTCOME_UNKNOWN" }; closed = true }
        override fun commit() { commits++; check(!failCommit) { "RUNTIME_START_FAILED" } }
        override fun abort(): Boolean { aborts++; return abortConfirmed }
    }
    @Test fun preparationDoesNotRunChildAndCloseDisposesOnlyUncommittedCandidate() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel()
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            assertEquals(0, channel.commits)
            prepared.close()
            prepared.close()
            assertEquals(1, channel.aborts)
            assertTrue(channel.closed)
            assertFailsWith<IllegalStateException> { prepared.commit() }
        } finally { Files.delete(log) }
    }
    @Test fun preparedCommitTransfersLifetimeExactlyOnce() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel()
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val runtime = prepared.commit()
            prepared.close()
            assertEquals(1, channel.commits)
            assertEquals(0, channel.aborts)
            assertFalse(channel.closed)
            assertTrue(runtime.isAlive)
            assertFailsWith<IllegalStateException> { prepared.commit() }
            channel.alive = false
            runtime.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun lostCommitAcknowledgmentConfirmsCandidateExitBeforeReturningFailure() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel().also { it.failCommit = true }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            assertFailsWith<IllegalStateException> { prepared.commit() }
            assertEquals(1, channel.aborts)
            assertTrue(channel.closed)
            assertFailsWith<IllegalStateException> { prepared.commit() }
        } finally { Files.delete(log) }
    }
    @Test fun unconfirmedCleanupTransfersRetainedRuntimeOwnershipThroughTypedFailure() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel().also { it.failCommit = true; it.abortConfirmed = false; it.lost = true }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.commit() }
            assertEquals("OUTCOME_UNKNOWN", failure.code)
            val retained = assertNotNull(failure.unresolvedRuntime)
            assertTrue(retained.isAlive)
            assertFalse(channel.closed)
            channel.childDead = true
            retained.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun confirmedAbortStillRetainsOwnershipWhenHandleClosureFails() {
        val log = Files.createTempFile("vpn-prepared-close-failure-", ".log")
        try {
            val channel = Channel().also {
                it.failClose = true
                it.lost = true
                it.childDead = true
            }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.close() }
            assertEquals("OUTCOME_UNKNOWN", failure.code)
            val retained = assertNotNull(failure.unresolvedRuntime)
            assertFalse(retained.isAlive, "Known child exit must survive a separate cleanup failure")
            assertFalse(channel.closed)
            prepared.close() // Ownership has transferred to the failure, never discarded or duplicated.
            assertEquals(1, channel.aborts)
            channel.failClose = false
            retained.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun exactChannelStopDoesNotPretendAcceptanceMeansExited() {
        val log = Files.createTempFile("vpn-runtime-handle-", ".log")
        try {
            val channel = Channel()
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            process.destroy()
            assertEquals(listOf(false), channel.stops)
            assertTrue(process.isAlive)
            assertFalse(process.waitFor(0, TimeUnit.MILLISECONDS))
            assertFailsWith<IllegalStateException> { process.close() }
            process.destroyForcibly()
            assertEquals(listOf(false, true), channel.stops)
            channel.alive = false
            assertTrue(process.waitFor(0, TimeUnit.MILLISECONDS))
            process.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun lostStatusRetainsRuntimeUntilRetainedChildHandleSignalsExit() {
        val log = Files.createTempFile("vpn-runtime-handle-", ".log")
        try {
            val channel = Channel().also { it.lost = true }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            assertTrue(process.isAlive)
            assertEquals(41L, process.pid())
            channel.childDead = true
            assertFalse(process.isAlive)
        } finally { Files.delete(log) }
    }
    @Test fun lostStopUsesOwnedNativeAbortAndRetainsUnconfirmedOutcome() {
        val log = Files.createTempFile("vpn-runtime-lost-stop-", ".log")
        try {
            val channel = Channel().also { it.lost = true; it.abortConfirmed = false }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            assertFailsWith<IllegalStateException> { process.destroyForcibly() }
            assertEquals(1, channel.aborts)
            assertTrue(process.isAlive)
            assertFalse(channel.closed)
            channel.abortConfirmed = true
            process.destroyForcibly()
            assertEquals(2, channel.aborts)
            assertFalse(process.isAlive)
            process.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }

    @Test fun authenticatedTerminalPublicationReconcilesOnlyAfterExactExit() {
        val log = Files.createTempFile("vpn-runtime-resource-terminal-", ".log")
        try {
            val registry = Registry()
            val job = resourceJob()
            val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
            val channel = Channel().also {
                it.alive = false
                it.reconciliation = nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED, cleaned = true)
            }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log, resources = retained)
            assertFalse(process.isAlive)
            process.close()
            assertTrue(process.resourceWarnings.isEmpty())
            assertTrue(registry.pending(job.scope).isEmpty())
            assertEquals(DesktopWindowsRuntimeResourceJobDisposition.PUBLICATION_AND_CLEANUP_CONFIRMED, registry.disposition)
        } finally { Files.delete(log) }
    }

    @Test fun missingTerminalEnvelopeRetainsJournalAndNeverPretendsPublication() {
        val log = Files.createTempFile("vpn-runtime-resource-missing-", ".log")
        try {
            val registry = Registry()
            val job = resourceJob()
            val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
            val channel = Channel().also { it.alive = false }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log, resources = retained)
            assertFalse(process.isAlive)
            assertEquals(DesktopRuntimeResourceDisposition.PENDING_PUBLICATION, process.resourceWarnings.single().disposition)
            assertFailsWith<DesktopRuntimeResourcePublicationFailure> { process.close() }
            assertSame(job, registry.pending(job.scope).single())
        } finally { Files.delete(log) }
    }

    private fun nativeResult(job: DesktopWindowsRuntimeResourceJob,
        disposition: DesktopWindowsNativeResourceDisposition, cleaned: Boolean) =
        DesktopWindowsNativeResourceReconciliation(job.jobId, job.resources.map {
            DesktopWindowsNativeResourceResult(it.resourceId, it.kind, disposition)
        }, cleaned)

    private fun resourceJob(): DesktopWindowsRuntimeResourceJob {
        val scope = DesktopWindowsRuntimeResourceScope("00000000-0000-0000-0000-000000000012",
            "00000000-0000-0000-0000-000000000013",
            DesktopWindowsResourceScopeRecord("C:\\fixture\\scope.json", "0".repeat(24), "1".repeat(24), 68, "2".repeat(64)))
        return DesktopWindowsRuntimeResourceJob("00000000-0000-0000-0000-000000000010", scope,
            listOf(DesktopWindowsRuntimeResourceEntry("00000000-0000-0000-0000-000000000011", DesktopWindowsRuntimeResourceKind.CACHE)),
            DesktopWindowsRuntimeResourceNativeOwner(123, 456, "S-1-5-21-1-2-3-1000"))
    }

    private class Registry : DesktopWindowsRuntimeResourceJournalRegistry {
        private var job: DesktopWindowsRuntimeResourceJob? = null
        var disposition: DesktopWindowsRuntimeResourceJobDisposition? = null
        override fun retain(job: DesktopWindowsRuntimeResourceJob) { check(this.job == null); this.job = job }
        override fun pending(scope: DesktopWindowsRuntimeResourceScope) = listOfNotNull(job)
        override fun reconcile(job: DesktopWindowsRuntimeResourceJob, disposition: DesktopWindowsRuntimeResourceJobDisposition) {
            check(this.job === job); this.job = null; this.disposition = disposition
        }
    }
}
