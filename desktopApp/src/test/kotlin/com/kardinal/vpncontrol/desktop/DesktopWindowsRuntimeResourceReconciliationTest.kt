package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.io.IOException
import java.nio.file.AccessDeniedException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DesktopWindowsRuntimeResourceReconciliationTest {
    @Test fun failedNativeRenamePreservesTheJournalAndRetainedLatestBytes() {
        val registry = MemoryResourceRegistry()
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        val warnings = retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.PENDING_PUBLICATION,
                ControlCode.PERSISTENCE_FAILED)
        }
        assertEquals(listOf(DesktopRuntimeResourceWarning(ControlCode.PERSISTENCE_FAILED, job.jobId,
            DesktopRuntimeResourceDisposition.PENDING_PUBLICATION)), warnings)
        assertSame(job, registry.pending(job.scope).single())
        assertEquals(0, registry.removals)
        assertEquals("latest owned cache", registry.retainedBytes)
        assertEquals("original destination identity", registry.journal)
    }

    @Test fun lostPublicationResponseOnlyInspectsAndKeepsItsExactCorrelation() {
        val registry = MemoryResourceRegistry()
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        val warning = retained.afterConfirmedExit { throw IOException("lost response") }.single()
        assertEquals(ControlCode.OUTCOME_UNKNOWN, warning.code)
        assertEquals(DesktopRuntimeResourceDisposition.PENDING_PUBLICATION, warning.disposition)
        assertSame(job, registry.pending(job.scope).single())
        val confirmed = retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED, cleaned = true)
        }
        assertTrue(confirmed.isEmpty())
        assertEquals(1, registry.removals)
        assertTrue(retained.afterConfirmedExit { error("Confirmed work must never be replayed") }.isEmpty())
    }

    @Test fun foreignMissingOrDuplicatedNativeResourcesCannotDisposeAnOwnedJournal() {
        val registry = MemoryResourceRegistry()
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        val right = nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED, cleaned = true)
        val observations = listOf(
            DesktopWindowsNativeResourceReconciliation(ID_OTHER, right.resources, true),
            DesktopWindowsNativeResourceReconciliation(job.jobId, emptyList(), true),
            DesktopWindowsNativeResourceReconciliation(job.jobId, right.resources + right.resources, true),
            DesktopWindowsNativeResourceReconciliation(job.jobId, listOf(DesktopWindowsNativeResourceResult(ID_OTHER,
                DesktopWindowsRuntimeResourceKind.CACHE, DesktopWindowsNativeResourceDisposition.PUBLISHED)), true),
        )
        observations.forEach { result ->
            assertEquals(ControlCode.OUTCOME_UNKNOWN, retained.afterConfirmedExit { result }.single().code)
        }
        assertSame(job, registry.pending(job.scope).single())
        assertEquals(0, registry.removals)
    }

    @Test fun nativeCommittedPublicationIsNotDowngradedByCorrelationDeletionFailure() {
        val registry = MemoryResourceRegistry().also { it.removeFailure = IOException("sharing reader") }
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        val warning = retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED, cleaned = true)
        }.single()
        assertEquals(ControlCode.PERSISTENCE_FAILED, warning.code)
        assertEquals(DesktopRuntimeResourceDisposition.COMMITTED_CLEANUP_PENDING, warning.disposition)
        assertSame(job, registry.pending(job.scope).single())
        registry.removeFailure = null
        assertTrue(retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED, cleaned = true)
        }.isEmpty())
        assertTrue(registry.pending(job.scope).isEmpty())
    }

    @Test fun knownPublicationEvidenceSurvivesLaterInspectionLoss() {
        val registry = MemoryResourceRegistry()
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        assertEquals(DesktopRuntimeResourceDisposition.COMMITTED_CLEANUP_PENDING,
            retained.afterConfirmedExit { nativeResult(job, DesktopWindowsNativeResourceDisposition.PUBLISHED) }.single().disposition)
        val lost = retained.afterConfirmedExit { throw IOException("broker disconnected") }.single()
        assertEquals(DesktopRuntimeResourceDisposition.COMMITTED_CLEANUP_PENDING, lost.disposition,
            "A lost cleanup reply erased authoritative publication evidence")
        assertSame(job, registry.pending(job.scope).single())
        assertEquals(0, registry.removals)
    }

    @Test fun knownNoHandoffRequiresProtectedCleanupBeforeRemovingTheRecord() {
        val registry = MemoryResourceRegistry()
        val job = resourceJob()
        val retained = DesktopWindowsRuntimeResourceReconciliation.retain(job, registry)
        assertEquals(1, retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF)
        }.size)
        assertEquals(0, registry.removals)
        assertTrue(retained.afterConfirmedExit {
            nativeResult(job, DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF, cleaned = true)
        }.isEmpty())
        assertEquals(DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF, registry.disposition)
    }

    @Test fun registryStorageAndCorruptionFailuresArePreparationFailures() {
        listOf(
            AccessDeniedException("private workspace") to "PERMISSION_DENIED",
            WindowsInstallNativeFailure(5) to "PERMISSION_DENIED",
            IllegalArgumentException("damaged correlation") to "PERSISTENCE_FAILED",
            IllegalStateException("BUSY") to "BUSY",
            IllegalStateException("CONFLICT") to "CONFLICT",
        ).forEach { (failure, code) ->
            val registry = MemoryResourceRegistry().also { it.retainFailure = failure }
            val result = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsRuntimeResourceReconciliation.retain(resourceJob(), registry)
            }
            assertEquals(code, result.code)
            assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, result.stage)
            assertEquals(0, registry.removals)
        }
    }

    private fun nativeResult(job: DesktopWindowsRuntimeResourceJob,
        disposition: DesktopWindowsNativeResourceDisposition, code: ControlCode? = null, cleaned: Boolean = false) =
        DesktopWindowsNativeResourceReconciliation(job.jobId, job.resources.map {
            DesktopWindowsNativeResourceResult(it.resourceId, it.kind, disposition, code)
        }, cleaned)

    private fun resourceJob() = DesktopWindowsRuntimeResourceJob(ID_JOB,
        DesktopWindowsRuntimeResourceScope(ID_SCOPE, ID_CONTROLLER,
            DesktopWindowsResourceScopeRecord("C:\\fixture\\scope.json", "0".repeat(24), "1".repeat(24), 68, "2".repeat(64))),
        listOf(DesktopWindowsRuntimeResourceEntry(ID_RESOURCE, DesktopWindowsRuntimeResourceKind.CACHE)),
        DesktopWindowsRuntimeResourceNativeOwner(123, 134000000000000000, "S-1-5-21-1-2-3-1000"))

    private class MemoryResourceRegistry : DesktopWindowsRuntimeResourceJournalRegistry {
        private var job: DesktopWindowsRuntimeResourceJob? = null
        var retainFailure: Exception? = null
        var removeFailure: Exception? = null
        var removals = 0
        var disposition: DesktopWindowsRuntimeResourceJobDisposition? = null
        var retainedBytes = "latest owned cache"
        var journal = "original destination identity"
        override fun retain(job: DesktopWindowsRuntimeResourceJob) { retainFailure?.let { throw it }; this.job = job }
        override fun pending(scope: DesktopWindowsRuntimeResourceScope) = listOfNotNull(job)
        override fun reconcile(job: DesktopWindowsRuntimeResourceJob, disposition: DesktopWindowsRuntimeResourceJobDisposition) {
            assertSame(this.job, job)
            removals++
            removeFailure?.let { throw it }
            this.job = null
            this.disposition = disposition
            retainedBytes = ""; journal = ""
        }
    }

    companion object {
        private const val ID_JOB = "00000000-0000-0000-0000-000000000010"
        private const val ID_RESOURCE = "00000000-0000-0000-0000-000000000011"
        private const val ID_SCOPE = "00000000-0000-0000-0000-000000000012"
        private const val ID_CONTROLLER = "00000000-0000-0000-0000-000000000013"
        private const val ID_OTHER = "00000000-0000-0000-0000-000000000014"
    }
}
