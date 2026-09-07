package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class DesktopInstallCorrelationTest {
    @Test fun authorizationFailureRetainsItsCodeAcrossOwnerReplacement() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace) { throw WindowsInstallNativeFailure(2) }
        journal.record(identity, JOB)
        journal.markNotStarted(identity, JOB, ControlCode.INTERACTION_REQUIRED)
        val reopened = DesktopInstallCorrelationJournal(workspace) { throw WindowsInstallNativeFailure(2) }
        val recovered = reopened.recover(identity)
        assertTrue(recovered.notStarted)
        assertFalse(recovered.blocksInstallation)
        assertEquals(ControlCode.INTERACTION_REQUIRED, recovered.code)
        reopened.markNotStarted(identity, JOB, ControlCode.INTERACTION_REQUIRED)
        assertFails { reopened.markNotStarted(identity, JOB, ControlCode.CANCELLED) }
        assertFails { reopened.markNotStarted(identity, JOB, ControlCode.OK) }
        assertFails { reopened.markNotStarted(identity, JOB, ControlCode.OUTCOME_UNKNOWN) }
    }

    @Test fun receiptAuthoritySurvivesRestartAndNeverFallsBackFromMachineFailure() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace)
        val binding = journal.record(identity, JOB, DesktopInstallReceiptAuthority.MACOS_USER_LOCAL)
        assertEquals(binding, journal.records().single())
        assertFails { journal.record(identity, JOB, DesktopInstallReceiptAuthority.MACHINE) }
        var legacyReads = 0
        val legacy = DesktopInstallCorrelationJournal(workspace) { legacyReads++; error("Machine reader must not receive local receipt") }
        assertEquals(ControlCode.OUTCOME_UNKNOWN, legacy.recover(identity).code)
        assertEquals(0, legacyReads)
        val routed = mutableListOf<DesktopInstallReceiptAuthority>()
        val restarted = DesktopInstallCorrelationJournal(workspace, readBoundReceipt = { record ->
            routed += record.receiptAuthority
            DesktopInstallJobReceipt(record.jobId, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        }, readProtectedReceipt = { error("No fallback") })
        assertEquals(ControlCode.OK, restarted.recover(identity).code)
        assertEquals(listOf(DesktopInstallReceiptAuthority.MACOS_USER_LOCAL), routed)
        val failed = DesktopInstallCorrelationJournal(workspace, readBoundReceipt = { throw java.io.IOException("untrusted") },
            readProtectedReceipt = { error("No fallback after selected authority failed") })
        assertTrue(failed.recover(identity).blocksInstallation)
    }

    @Test fun authorityIsStrictAndAbsentLegacyFieldMeansMachine() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace)
        journal.record(identity, JOB)
        val path = Files.list(workspace).use { it.findFirst().orElseThrow() }
        val legacy = Files.readString(path)
        assertFalse(legacy.contains("receiptAuthority"))
        assertEquals(DesktopInstallReceiptAuthority.MACHINE, journal.records().single().receiptAuthority)
        for (bad in listOf("\"OTHER\"", "null", "1")) {
            Files.writeString(path, legacy.dropLast(1) + ",\"receiptAuthority\":$bad}")
            assertFails { journal.records() }
        }
    }

    @Test fun provenNoCoordinatorCanCancelLocallyButNeverOverrideProtectedOrUnknownOutcomes() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val next = DesktopInstallCorrelation("next", "request", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace) { throw WindowsInstallNativeFailure(2) }
        journal.record(identity, JOB)
        journal.markNotStarted(identity, JOB)
        journal.markNotStarted(identity, JOB)
        val recovery = journal.recover(identity)
        assertEquals(ControlCode.CANCELLED, recovery.code)
        assertTrue(recovery.notStarted)
        assertNull(recovery.receipt)
        assertFalse(recovery.blocksInstallation)
        journal.requireNew(next)
        assertFails { journal.requireNew(identity) }
        val inaccessible = DesktopInstallCorrelationJournal(workspace) { throw WindowsInstallNativeFailure(5) }
        assertTrue(inaccessible.recover(identity).blocksInstallation)
        assertFails { inaccessible.markNotStarted(identity, JOB) }
        val launched = DesktopInstallCorrelationJournal(workspace) { job ->
            DesktopInstallJobReceipt(job, 3, DesktopInstallJobPhase.INSTALLING, ControlCode.OK)
        }
        assertEquals(ControlCode.ACCEPTED, launched.recover(identity).code)
        assertTrue(launched.recover(identity).blocksInstallation)
        assertFalse(launched.recover(identity).notStarted)
        assertFails { launched.markNotStarted(identity, JOB) }
    }

    @Test fun terminalHistoryIsPrunedWithoutRemovingUnresolvedEntriesOrCappingLifetime() = fixture { workspace ->
        val waiting = DesktopInstallCorrelation("waiting", "waiting", "waiting")
        val journal = DesktopInstallCorrelationJournal(workspace, terminalHistoryLimit = 2) { job ->
            if (job == JOB) throw WindowsInstallNativeFailure(2)
            DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        }
        journal.record(waiting, JOB)
        repeat(270) { index ->
            journal.record(DesktopInstallCorrelation("controller", "request-$index", "operation-$index"),
                java.util.UUID.nameUUIDFromBytes("job-$index".toByteArray()).toString())
        }
        assertTrue(journal.records().size <= 4) // Two retained terminals, newest record, unresolved job.
        assertEquals(JOB, journal.recover(waiting).binding!!.jobId)
        assertTrue(journal.recover(waiting).blocksInstallation)
    }

    @Test fun abandonedHistoryPrunesItsExactDispositionButKeepsUnknownProof() = fixture { workspace ->
        val journal = DesktopInstallCorrelationJournal(workspace, terminalHistoryLimit = 1) { throw WindowsInstallNativeFailure(2) }
        repeat(5) { index ->
            val identity = DesktopInstallCorrelation("controller", "request-$index", "operation-$index")
            val job = java.util.UUID.nameUUIDFromBytes("job-$index".toByteArray()).toString()
            journal.record(identity, job)
            journal.markNotStarted(identity, job)
        }
        assertTrue(journal.records().size <= 2)
        assertTrue(Files.list(workspace).use { it.count() } <= 4)
    }

    @Test fun newWorkerAdmissionRequiresAllPreviousProtectedOutcomesAndNeverReplaysIdentity() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val next = DesktopInstallCorrelation("new-controller", "next-request", "next-operation")
        DesktopInstallCorrelationJournal(workspace).record(identity, JOB)
        val unknown = DesktopInstallCorrelationJournal(workspace) { throw WindowsInstallNativeFailure(2) }
        assertEquals("CONFLICT", assertFails { unknown.requireNew(identity) }.message)
        assertEquals("BUSY", assertFails { unknown.requireNew(next) }.message)
        val terminal = DesktopInstallCorrelationJournal(workspace) { job ->
            DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        }
        terminal.requireNew(next)
        assertEquals("CONFLICT", assertFails { terminal.requireNew(identity) }.message)
        assertEquals(1, terminal.records().size)
    }

    @Test fun bindingSurvivesNewJournalInstanceAndQueriesOnlyItsProtectedJob() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request 東京", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace)
        val record = journal.record(identity, JOB)
        assertEquals(record, journal.record(identity, JOB))
        val calls = mutableListOf<String>()
        val restarted = DesktopInstallCorrelationJournal(workspace) { job ->
            calls += job
            DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        }
        val recovery = restarted.recover(identity)
        assertEquals(record, recovery.binding)
        assertEquals(ControlCode.OK, recovery.code)
        assertFalse(recovery.blocksInstallation)
        assertEquals(listOf(JOB), calls)
    }

    @Test fun unknownReceiptNeverTurnsJournalIntoAuthorizationOrReplay() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        DesktopInstallCorrelationJournal(workspace).record(identity, JOB)
        for (read in listOf<(String) -> DesktopInstallJobReceipt>(
            { throw WindowsInstallNativeFailure(2) },
            { throw IllegalArgumentException("Untrusted receipt") },
            { DesktopInstallJobReceipt(OTHER_JOB, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK) },
        )) {
            val recovery = DesktopInstallCorrelationJournal(workspace, readProtectedReceipt = read).recover(identity)
            assertEquals(ControlCode.OUTCOME_UNKNOWN, recovery.code)
            assertTrue(recovery.blocksInstallation)
            assertNull(recovery.receipt)
        }
    }

    @Test fun eachCorrelationComponentAndNativeJobRemainImmutable() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        val journal = DesktopInstallCorrelationJournal(workspace)
        journal.record(identity, JOB)
        assertFails { journal.record(identity, OTHER_JOB) }
        assertFails { journal.record(identity.copy(requestId = "other"), JOB) }
        assertFails { journal.record(identity.copy(operationId = "other"), OTHER_JOB) }
        assertFails { journal.record(identity.copy(controllerId = "other"), JOB) }
        assertEquals(listOf(identity), journal.records().map { it.correlation })
    }

    @Test fun separateWorkspacesCannotRecoverEachOthersBindingsEvenWhenCopied() = fixture { workspace ->
        val first = privateDirectory(workspace, "one")
        val second = privateDirectory(workspace, "two")
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        DesktopInstallCorrelationJournal(first).record(identity, JOB)
        var reads = 0
        val other = DesktopInstallCorrelationJournal(second) { reads++; error("Must not consult receipt") }
        assertEquals(ControlCode.NOT_FOUND, other.recover(identity).code)
        Files.list(first).use { paths -> paths.forEach { Files.copy(it, second.resolve(it.fileName)) } }
        assertFails { other.records() }
        assertEquals(0, reads)
    }

    @Test fun missingCorrelationsDoNotConsultProtectedStoreAndPendingPhasesBlock() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        var reads = 0
        val journal = DesktopInstallCorrelationJournal(workspace) { job ->
            reads++
            DesktopInstallJobReceipt(job, 3, DesktopInstallJobPhase.INSTALLING, ControlCode.OK)
        }
        assertEquals(ControlCode.NOT_FOUND, journal.recover(identity).code)
        assertEquals(0, reads)
        journal.record(identity, JOB)
        assertTrue(journal.recover(identity).blocksInstallation)
        assertEquals(ControlCode.ACCEPTED, journal.recover(identity).code)
        assertEquals(JOB, journal.recoverAll().single().binding!!.jobId)
    }

    @Test fun malformedOrOversizedJournalBlocksBeforeProtectedReads() = fixture { workspace ->
        val identity = DesktopInstallCorrelation("controller", "request", "operation")
        DesktopInstallCorrelationJournal(workspace).record(identity, JOB)
        val path = Files.list(workspace).use { it.findFirst().orElseThrow() }
        for (bad in listOf("{}", "x".repeat(4097))) {
            Files.writeString(path, bad)
            assertFails { DesktopInstallCorrelationJournal(workspace) { error("Must not consult receipt") }.records() }
        }
        assertFails { DesktopInstallCorrelation("controller", "\n", "operation") }
    }

    private fun fixture(action: (Path) -> Unit) {
        val workspace = Files.createTempDirectory("install-correlation-東京")
        try { action(workspace) }
        finally { Files.walk(workspace).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private fun privateDirectory(parent: Path, name: String): Path = if ("posix" in parent.fileSystem.supportedFileAttributeViews()) {
        Files.createDirectory(parent.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    } else {
        Files.createDirectory(parent.resolve(name))
    }

    companion object {
        private const val JOB = "11111111-2222-3333-4444-555555555555"
        private const val OTHER_JOB = "22222222-2222-3333-4444-555555555555"
    }
}
