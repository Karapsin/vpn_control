package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.runBlocking
import java.nio.file.AccessDeniedException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import kotlin.test.*

class DesktopLinuxInstallCorrelationTest {
    private val correlation = DesktopInstallCorrelation("controller 東京", "request-original", "operation-original")
    private val job = "00000000-0000-0000-0000-000000000031"
    private class Prepared(override val jobId: String) : DesktopPreparedInstall {
        var cancels = 0
        var commits = 0
        var closes = 0
        var outcome = Result.failure<Unit>(IllegalStateException("OUTCOME_UNKNOWN"))
        override suspend fun commit(): Result<Unit> { commits++; return Result.success(Unit) }
        override fun cancel(): Result<Unit> { cancels++; return outcome }
        override fun close() { closes++ }
    }

    @Test fun requireNewRejectsReplayAndUnknownPriorJobBeforePlatformStaging() = runBlocking { fixture { directory ->
        val journal = DesktopInstallCorrelationJournal(directory) { throw NoSuchFileException("status.json") }
        journal.record(correlation, job)
        val installer = DesktopLinuxInstaller(directory, journal, isLinux = { true })
        val asset = UpdateAsset(UpdatePlatform.LINUX, "arm64", UpdatePackageType.DEB, "1.0.0", "test.deb",
            "https://example.invalid/test.deb", "a".repeat(64), 1)
        val before = Files.list(directory).use { it.toList() }
        assertEquals("CONFLICT", installer.prepare(directory.resolve("absent.deb"), asset, correlation).exceptionOrNull()?.message)
        val next = DesktopInstallCorrelation("new-controller", "new-request", "new-operation")
        assertEquals("BUSY", installer.prepare(directory.resolve("absent.deb"), asset, next).exceptionOrNull()?.message)
        assertEquals(before, Files.list(directory).use { it.toList() })
    } }

    @Test fun newAdapterRecoversExactIdentifiersFromProtectedReceiptWithoutLaunching() = runBlocking { fixture { directory ->
        DesktopInstallCorrelationJournal(directory).record(correlation, job)
        val queried = mutableListOf<String>()
        var phase = DesktopInstallJobPhase.INSTALLING
        fun adapter() = DesktopLinuxInstaller(directory, DesktopInstallCorrelationJournal(directory) { requested ->
            queried += requested
            DesktopInstallJobReceipt(requested, 5, phase, ControlCode.OK)
        })
        val pending = adapter().recoverCorrelations().getOrThrow().single()
        assertEquals(correlation, pending.binding?.correlation)
        assertEquals(job, pending.binding?.jobId)
        assertEquals(ControlCode.ACCEPTED, pending.code)
        assertTrue(pending.blocksInstallation)
        phase = DesktopInstallJobPhase.SUCCEEDED
        val terminal = adapter().recoverCorrelations().getOrThrow().single()
        assertEquals(ControlCode.OK, terminal.code)
        assertFalse(terminal.blocksInstallation)
        assertEquals(listOf(job, job), queried)
    } }

    @Test fun onlyNeverAttemptedCoordinatorAndAbsentOrExitedWatcherProveNotStarted() {
        assertTrue(linuxInstallDefinitelyNotStarted(false, null))
        assertTrue(linuxInstallDefinitelyNotStarted(false, false))
        assertFalse(linuxInstallDefinitelyNotStarted(false, true))
        for (alive in listOf(null, false, true)) assertFalse(linuxInstallDefinitelyNotStarted(true, alive))
    }

    @Test fun reservedAuthorizationRejectionRequiresAnExitedWatcherAndNeverAcceptsWorkerExitCodes() {
        for (rejection in listOf(126, 127)) {
            assertTrue(linuxInstallDefinitelyNotStarted(true, false, rejection))
            assertTrue(linuxInstallDefinitelyNotStarted(true, null, rejection))
            assertFalse(linuxInstallDefinitelyNotStarted(true, true, rejection))
        }
        for (workerExit in listOf(null, 0, 1, 125, 130, 137, 255)) {
            assertFalse(linuxInstallDefinitelyNotStarted(true, false, workerExit))
        }
    }

    @Test fun rejectedAuthorizationRecoversExactDurableCancellationAndAllowsANewAttempt() = runBlocking { fixture { directory ->
        val journal = DesktopInstallCorrelationJournal(directory) { throw NoSuchFileException("status.json") }
        journal.record(correlation, job)
        val delegate = Prepared(job)
        var confirmed = 0
        val prepared = DesktopLinuxUnstartedCancellation(delegate,
            { linuxInstallDefinitelyNotStarted(true, false, 126) },
            { journal.markNotStarted(correlation, job) }, { confirmed++ })
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(0, delegate.cancels)
        assertEquals(1, confirmed)
        val recovered = journal.recover(correlation)
        assertEquals(correlation, recovered.binding?.correlation)
        assertEquals(job, recovered.binding?.jobId)
        assertEquals(ControlCode.CANCELLED, recovered.code)
        assertTrue(recovered.notStarted)
        assertFalse(recovered.blocksInstallation)
        assertFails { journal.requireNew(correlation) }
        journal.requireNew(DesktopInstallCorrelation("next-controller", "next-request", "next-operation"))
        prepared.close()
    } }

    @Test fun rejectedAuthorizationCannotOverrideAReceiptThatAppearedBeforeDisposition() = runBlocking { fixture { directory ->
        val protected = DesktopInstallJobReceipt(job, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
        val journal = DesktopInstallCorrelationJournal(directory) { protected }
        journal.record(correlation, job)
        val prepared = DesktopLinuxUnstartedCancellation(Prepared(job),
            { linuxInstallDefinitelyNotStarted(true, false, 127) },
            { journal.markNotStarted(correlation, job) }, { error("Must not confirm cancellation") })
        assertTrue(prepared.cancel().isFailure)
        val recovered = journal.recover(correlation)
        assertFalse(recovered.notStarted)
        assertTrue(recovered.blocksInstallation)
        assertEquals(protected, recovered.receipt)
        prepared.close()
    } }

    @Test fun settlementRequiresExactReReadProtectedTerminalAndCorrelation() = runBlocking { fixture { directory ->
        DesktopInstallCorrelationJournal(directory).record(correlation, job)
        val terminal = DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED)
        var protected = terminal
        val adapter = DesktopLinuxInstaller(directory, DesktopInstallCorrelationJournal(directory) { protected })
        assertTrue(adapter.releaseCompleted(correlation, terminal).isSuccess)
        assertTrue(adapter.releaseCompleted(correlation.copy(requestId = "substitute"), terminal).isFailure)
        assertTrue(adapter.releaseCompleted(correlation, terminal.copy(sequence = 6)).isFailure)
        protected = DesktopInstallJobReceipt(job, 4, DesktopInstallJobPhase.INSTALLING, ControlCode.OK)
        assertTrue(adapter.releaseCompleted(correlation, terminal).isFailure)
        assertTrue(adapter.releaseCompleted(correlation, protected).isFailure)
    } }

    @Test fun localCancellationBecomesDurableOnlyAfterJournalPublication() = runBlocking { fixture { directory ->
        val journal = DesktopInstallCorrelationJournal(directory) { throw NoSuchFileException("status.json") }
        journal.record(correlation, job)
        val delegate = Prepared(job)
        var confirmed = 0
        val prepared = DesktopLinuxUnstartedCancellation(delegate, { true }, { journal.markNotStarted(correlation, job) }, { confirmed++ })
        assertTrue(prepared.cancel().isSuccess)
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(1, confirmed)
        assertEquals(0, delegate.cancels)
        assertTrue(prepared.commit().isFailure)
        assertEquals(0, delegate.commits)
        val recovery = DesktopLinuxInstaller(directory, DesktopInstallCorrelationJournal(directory) {
            throw NoSuchFileException("status.json")
        }).recoverCorrelations().getOrThrow().single()
        assertTrue(recovery.notStarted)
        assertEquals(ControlCode.CANCELLED, recovery.code)
        assertFalse(recovery.blocksInstallation)
        prepared.close(); prepared.close()
        assertEquals(1, delegate.closes)
    } }

    @Test fun inaccessibleReceiptCannotBeRetiredByLocalProofAndFailedProofIsRetryable() = runBlocking { fixture { directory ->
        val journal = DesktopInstallCorrelationJournal(directory) { throw AccessDeniedException("status.json") }
        journal.record(correlation, job)
        var confirmed = 0
        val prepared = DesktopLinuxUnstartedCancellation(Prepared(job), { true }, { journal.markNotStarted(correlation, job) }, { confirmed++ })
        assertTrue(prepared.cancel().isFailure)
        assertTrue(prepared.cancel().isFailure)
        assertEquals(0, confirmed)
        assertTrue(journal.recover(correlation).blocksInstallation)
        assertFalse(journal.recover(correlation).notStarted)
        prepared.close()
    } }

    @Test fun attemptedCoordinatorKeepsMissingReceiptUnknownUntilProtectedCancellation() = runBlocking { fixture { directory ->
        val journal = DesktopInstallCorrelationJournal(directory) { throw NoSuchFileException("status.json") }
        journal.record(correlation, job)
        val delegate = Prepared(job)
        var localDispositions = 0
        val prepared = DesktopLinuxUnstartedCancellation(delegate,
            { linuxInstallDefinitelyNotStarted(true, false) }, { localDispositions++ }, { error("Local cancellation") })
        assertTrue(prepared.cancel().isFailure)
        assertEquals(1, delegate.cancels)
        assertEquals(0, localDispositions)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, journal.recover(correlation).code)
        assertTrue(journal.recover(correlation).blocksInstallation)
        delegate.outcome = Result.success(Unit)
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(2, delegate.cancels)
        assertEquals(0, localDispositions)
        prepared.close()
    } }

    private suspend fun fixture(block: suspend (Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-linux-install-correlation-").toRealPath()
        try { block(directory) }
        finally {
            Files.list(directory).use { it.toList() }.forEach(Files::delete)
            Files.delete(directory)
        }
    }
}
