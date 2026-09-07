package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.util.UUID
import kotlin.test.*

class DesktopWindowsWorkspaceResourceJournalRegistryTest {
    @Test fun coldOwnerRecoversOriginalCorrelationAfterLostPublicationReplyWithoutReplaying() {
        val storage = Storage()
        val original = scope()
        val job = job(original)
        val registry = registry(storage, original)
        storage.loseReply = true
        assertFails { registry.retain(job) }
        storage.loseReply = false
        val replacement = scope(original.scopeId, UUID.randomUUID().toString(), original.record)
        val reopened = registry(storage, replacement)
        val recovered = reopened.pending(replacement).single()
        assertEquals(job.jobId, recovered.jobId)
        assertEquals(original.controllerId, recovered.scope.controllerId)
        assertEquals(job.nativeOwner.processId, recovered.nativeOwner.processId)
        assertEquals(job.nativeOwner.creationFileTime, recovered.nativeOwner.creationFileTime)
        assertEquals(job.nativeOwner.sid, recovered.nativeOwner.sid)
        assertEquals(job.resources.single().resourceId, recovered.resources.single().resourceId)
        assertEquals(1, storage.publications)
        assertFails { reopened.retain(job) }
        reopened.reconcile(recovered, DesktopWindowsRuntimeResourceJobDisposition.PUBLICATION_AND_CLEANUP_CONFIRMED)
        assertTrue(reopened.pending(replacement).isEmpty())
    }

    @Test fun capacityNeverEvictsUnresolvedRecordsAndExactRetryIsIdempotent() {
        val storage = Storage(); val scope = scope(); val registry = registry(storage, scope)
        val jobs = List(8) { job(scope) }
        jobs.forEach(registry::retain)
        registry.retain(jobs.first())
        assertEquals(8, storage.publications)
        assertEquals("BUSY", assertFails { registry.retain(job(scope)) }.message)
        assertEquals(jobs.map { it.jobId }.toSet(), registry.pending(scope).map { it.jobId }.toSet())
        registry.reconcile(jobs.first(), DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF)
        registry.retain(job(scope))
        assertEquals(8, registry.pending(scope).size)
    }

    @Test fun copiedScopeBytesAtDifferentFileIdentityCannotReadOrDisposeOldJobs() {
        val storage = Storage(); val old = scope(); val job = job(old)
        registry(storage, old).retain(job)
        val copied = scope(old.scopeId, UUID.randomUUID().toString(), record(file = "b".repeat(24)))
        val reopened = registry(storage, copied)
        assertFails { reopened.pending(copied) }
        assertFails { reopened.reconcile(job, DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF) }
        assertEquals(1, storage.bytes.size)
    }

    @Test fun conflictingResourceOrOriginCannotOverwriteOrReconcileExactJob() {
        val storage = Storage(); val scope = scope(); val job = job(scope); val registry = registry(storage, scope)
        registry.retain(job)
        val different = job(scope, job.jobId)
        assertFails { registry.retain(different) }
        assertFails { registry.reconcile(different, DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF) }
        assertEquals(1, storage.publications)
        assertEquals(job.resources.single().resourceId, registry.pending(scope).single().resources.single().resourceId)
    }

    @Test fun corruptOrRacingRecordIsPreservedWithoutRepair() {
        val storage = Storage(); val scope = scope(); val job = job(scope); val registry = registry(storage, scope)
        registry.retain(job)
        storage.bytes[job.jobId] = storage.bytes.getValue(job.jobId) + byteArrayOf(10)
        assertFails { registry.pending(scope) }
        assertFails { registry.retain(job(scope)) }
        assertEquals(1, storage.publications)
        storage.bytes.clear(); registry.retain(job)
        storage.raceRemoval = true
        assertFails { registry.reconcile(job, DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF) }
        assertTrue(storage.bytes.containsKey(job.jobId))
    }

    @Test fun failedRemovalRetainsOriginalJobForLaterNativeReconciliation() {
        val storage = Storage(); val scope = scope(); val job = job(scope); val registry = registry(storage, scope)
        registry.retain(job)
        storage.failRemoval = true
        assertFails { registry.reconcile(job, DesktopWindowsRuntimeResourceJobDisposition.PUBLICATION_AND_CLEANUP_CONFIRMED) }
        assertEquals(job.jobId, registry(storage, scope).pending(scope).single().jobId)
    }

    @Test fun nativePrivateRecordsRecoverAcrossOwnersAndDeleteOnlyExactRetainedObjects() {
        org.junit.Assume.assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        org.junit.Assume.assumeTrue(System.getenv("VPN_CONTROL_TEST_WINDOWS_USER_FILES") == "1")
        val directory = java.nio.file.Files.createTempDirectory("vpn-resource-journal-Ω-")
        try {
            val originalProvider = DesktopWindowsWorkspaceResourceScope(directory, UUID.randomUUID().toString())
            val original = originalProvider.current()
            val originalRegistry = originalProvider.journals()
            val job = job(original)
            originalRegistry.retain(job)
            originalRegistry.retain(job)
            val nextProvider = DesktopWindowsWorkspaceResourceScope(directory, UUID.randomUUID().toString())
            val next = nextProvider.current()
            val registry = nextProvider.journals()
            val recovered = registry.pending(next).single()
            assertEquals(job.jobId, recovered.jobId)
            assertEquals(original.controllerId, recovered.scope.controllerId)
        assertEquals(job.nativeOwner.processId, recovered.nativeOwner.processId)
        assertEquals(job.nativeOwner.creationFileTime, recovered.nativeOwner.creationFileTime)
        assertEquals(job.nativeOwner.sid, recovered.nativeOwner.sid)
            registry.reconcile(recovered, DesktopWindowsRuntimeResourceJobDisposition.PUBLICATION_AND_CLEANUP_CONFIRMED)
            assertTrue(registry.pending(next).isEmpty())
            assertTrue(java.nio.file.Files.exists(directory.resolve("runtime-resource-scope.json")))
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun reusedPidOrChangedNativeOwnerCannotDisposeRetainedJob() {
        val storage = Storage(); val scope = scope(); val job = job(scope); val registry = registry(storage, scope)
        registry.retain(job)
        val original = job.nativeOwner
        for (owner in listOf(
            DesktopWindowsRuntimeResourceNativeOwner(original.processId + 1, original.creationFileTime, original.sid),
            DesktopWindowsRuntimeResourceNativeOwner(original.processId, original.creationFileTime + 1, original.sid),
            DesktopWindowsRuntimeResourceNativeOwner(original.processId, original.creationFileTime, "S-1-5-21-1-2-3-1002"))) {
            val forged = DesktopWindowsRuntimeResourceJob(job.jobId, scope, job.resources, owner)
            assertFails { registry.retain(forged) }
            assertFails { registry.reconcile(forged, DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF) }
        }
        assertEquals(1, storage.publications)
        assertEquals(job.jobId, registry.pending(scope).single().jobId)
    }

    private fun registry(storage: Storage, scope: DesktopWindowsRuntimeResourceScope) =
        DesktopWindowsWorkspaceResourceJournalRegistry(Path.of("unused"), { scope }, storage)
    private fun record(file: String = "a".repeat(24)) = DesktopWindowsResourceScopeRecord(
        "C:\\Users\\User Ω\\workspace\\runtime-resource-scope.json", "1".repeat(24), file, 68L, "e".repeat(64))
    private fun scope(id: String = UUID.randomUUID().toString(), controller: String = UUID.randomUUID().toString(),
        record: DesktopWindowsResourceScopeRecord = record()) = DesktopWindowsRuntimeResourceScope(id, controller, record)
    private fun job(scope: DesktopWindowsRuntimeResourceScope, id: String = UUID.randomUUID().toString()) =
        DesktopWindowsRuntimeResourceJob(id, scope, listOf(DesktopWindowsRuntimeResourceEntry(
            UUID.randomUUID().toString(), DesktopWindowsRuntimeResourceKind.CACHE)),
            DesktopWindowsRuntimeResourceNativeOwner(123L, 456789L, "S-1-5-21-1-2-3-1001"))

    private class Storage : DesktopWindowsResourceCorrelationStorage {
        val bytes = linkedMapOf<String, ByteArray>()
        var publications = 0
        var loseReply = false
        var failRemoval = false
        var raceRemoval = false
        override fun readAll() = bytes.mapValues { it.value.copyOf() }
        override fun publish(jobId: String, bytes: ByteArray) {
            check(jobId !in this.bytes)
            this.bytes[jobId] = bytes.copyOf(); publications++
            if (loseReply) error("OUTCOME_UNKNOWN")
        }
        override fun removeExact(jobId: String, bytes: ByteArray) {
            if (failRemoval) error("PERMISSION_DENIED")
            if (raceRemoval) this.bytes[jobId] = byteArrayOf(1)
            check(this.bytes.getValue(jobId).contentEquals(bytes)) { "CONFLICT" }
            this.bytes.remove(jobId)
        }
    }
}
