package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePlatform
import com.kardinal.vpncontrol.UpdatePackageType
import com.sun.jna.platform.win32.WinNT
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import kotlinx.coroutines.runBlocking
import kotlin.test.*

/** Real private journal/codec plus a mechanical byte/object/handle syscall model; never a verdict mock. */
class DesktopWindowsDeniedInputCleanupTest {
    @Test fun sameOwnerServiceMaintenanceDisposesExactDeniedInputsAndPreservesCancellationHistory() = runBlocking {
        fixture { f ->
            f.deny()
            val before = f.journalBytes()
            var state = MainUiState(isVpnRunning = true)
            val installer = DesktopWindowsInstaller(f.workspace, f.journal, f.cleanup)
            val service = DesktopUpdateService({ state }, { state = it(state) }, f.workspace.resolve("updates"),
                osName = "Windows", workspaceDirectory = f.workspace, windowsInstallerFactory = { installer })
            assertTrue(service.recoverInstallCorrelations().isSuccess)
            assertTrue(f.native.nodes.containsKey(f.packagePath), "Inspection must remain read-only")
            service.reconcileTerminalInstallInputs(f.correlation.controllerId).getOrThrow()
            assertFalse(f.native.nodes.containsKey(f.inputPath), "Frozen Mac-only wiring/current-owner guard leaves the input here")
            assertEquals(before, f.journalBytes())
            val recovered = service.recoverInstallCorrelations().getOrThrow().single()
            assertEquals(ControlCode.CANCELLED, recovered.code)
            assertEquals(ControlCode.OK, recovered.cleanupCode)
            assertTrue(recovered.notStarted && state.isVpnRunning)
            f.native.assertClosed()
        }
    }

    @Test fun existingMaintenanceSeamRunsSameOwnerOnlyWhenWindowsOptsIn() = fixture { f ->
        f.deny()
        val maintenance = DesktopInstallInputCleanup({ Result.success(f.journal.recoverAll()) },
            release = { _, _ -> error("No protected receipt") }, releaseNotStarted = f.cleanup::release)
        assertTrue(maintenance.reconcile(f.correlation.controllerId).isSuccess)
        assertTrue(f.native.nodes.containsKey(f.packagePath))
        maintenance.releaseCurrentOwnerNotStarted = true
        maintenance.reconcile(f.correlation.controllerId).getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.inputPath), "Frozen unconditional same-controller skip is actual RED")
        assertEquals(ControlCode.CANCELLED, maintenance.decorate(f.journal.recoverAll()).single().code)
        assertEquals(ControlCode.OK, maintenance.decorate(f.journal.recoverAll()).single().cleanupCode)
        f.native.assertClosed()
    }

    @Test fun denialClosesEveryOriginalHolderBeforeDisposal() = fixture { f ->
        val events = mutableListOf<Int>()
        var failOnce = true
        val holders = mutableListOf<AutoCloseable>(
            AutoCloseable { events += 1 },
            AutoCloseable { events += 2; if (failOnce) { failOnce = false; error("close failure") } },
            AutoCloseable { events += 3 })
        f.journal.markNotStarted(f.correlation, f.job)
        assertTrue(f.cleanup.retainNativeDenial(f.witness, 1223, holders).isFailure)
        assertEquals(listOf(3, 2, 1), events)
        assertEquals(1, holders.size)
        assertTrue(f.cleanup.blocksPreparation())
        f.cleanup.release(f.record()).getOrThrow()
        assertTrue(holders.isEmpty())
        assertFalse(f.cleanup.blocksPreparation())
        assertEquals(listOf(3, 2, 1, 2), events)
        f.native.assertClosed()
    }

    @Test fun aCancellationStringAndOtherNativeCodesCannotGrantDisposalAuthority() = fixture { f ->
        f.journal.markNotStarted(f.correlation, f.job)
        for (code in listOf(0, 5, 2, 1460)) {
            assertTrue(f.cleanup.retainNativeDenial(f.witness, code, mutableListOf()).isFailure)
        }
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertTrue(f.native.nodes.containsKey(f.packagePath))
        assertTrue(f.native.deletions.isEmpty())
        f.native.assertClosed()
    }

    @Test fun legacyColdPresentInputsRemainTerminalCancellationWithCleanupFailure() = fixture { f ->
        f.journal.markNotStarted(f.correlation, f.job)
        val maintenance = DesktopInstallInputCleanup({ Result.success(f.journal.recoverAll()) },
            release = { _, _ -> error("No receipt") }, releaseNotStarted = f.cleanup::release)
        assertTrue(maintenance.reconcile("new-owner").isFailure)
        val record = maintenance.decorate(f.journal.recoverAll()).single()
        assertEquals(ControlCode.CANCELLED, record.code)
        assertEquals(ControlCode.PERSISTENCE_FAILED, record.cleanupCode)
        assertTrue(f.native.nodes.containsKey(f.packagePath))
        assertFalse(f.cleanup.inputAbsent(f.binding))
        f.native.assertClosed()
    }

    @Test fun liveUnknownChangedCorrelationAndProtectedJobNeverDeleteInput() {
        val changes: List<(WindowsDeniedInputFixture) -> DesktopInstallCorrelationRecovery> = listOf(
            { it.pending = true; it.record() },
            { it.protectedPresent = true; it.record() },
            { it.protectedInaccessible = true; it.record() },
            { it.record().copy(code = ControlCode.OUTCOME_UNKNOWN, notStarted = false) },
            { it.record().copy(binding = it.binding.copy(correlation = it.correlation.copy(requestId = "foreign"))) })
        for (change in changes) fixture { f ->
            f.deny(); val record = change(f)
            assertTrue(f.cleanup.release(record).isFailure)
            assertTrue(f.native.deletions.isEmpty())
            f.native.assertClosed()
        }
    }

    @Test fun mutatedNativeObjectsRequestsAclAndContentsAreRejectedBeforeAnyDeletion() {
        val changes: List<(WindowsDeniedInputFixture) -> Unit> = listOf(
            { it.native.nodes.getValue(it.packagePath).info = it.native.nodes.getValue(it.packagePath).info.copy(links = 2) },
            { it.native.nodes.getValue(it.packagePath).info = it.native.nodes.getValue(it.packagePath).info.copy(owner = "S-1-5-21-9-9-9-9999") },
            { it.native.nodes.getValue(it.packagePath).info = it.native.nodes.getValue(it.packagePath).info.copy(attributes = 0x400) },
            { it.native.nodes.getValue(it.inputPath).info = it.native.nodes.getValue(it.inputPath).info.copy(reparseTag = 1) },
            { it.native.nodes.getValue(it.packagePath).info = it.native.nodes.getValue(it.packagePath).info.copy(dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, "S-1-5-32-544"))) },
            { it.native.nodes.getValue(it.inputPath).identity = "e".repeat(48) },
            { it.native.nodes.getValue(it.packagePath).identity = "e".repeat(48) },
            { it.native.nodes.getValue(it.packagePath).bytes[0] = 0 },
            { it.native.nodes.getValue(it.requestPath).bytes = it.request.copy(ownerPid = 333).encode() },
            { it.native.nodes.getValue(it.requestPath).bytes = it.request.copy(stateDirectory = "C:\\foreign").encode() },
            { it.native.nodes.getValue(it.requestPath).bytes = ByteArray(DesktopWindowsInstallRequest.MAX_BYTES + 1) },
            { it.native.nodes.getValue(it.packagePath).persistentAcl = false },
            { it.native.put(it.inputPath + "\\commit.json", false, byteArrayOf(1)) },
            { it.native.put(it.inputPath + "\\foreign", false, byteArrayOf(1)) })
        for ((index, change) in changes.withIndex()) fixture { f ->
            f.deny(); change(f)
            assertTrue(f.cleanup.release(f.record()).isFailure, "Mutation $index")
            assertTrue(f.native.deletions.isEmpty(), "Mutation $index deleted something")
            f.native.assertClosed()
        }
    }

    @Test fun deletionFailureRetainsTruthfulCancellationAndRetriesCleanupOnly() = fixture { f ->
        f.deny(); val before = f.journalBytes()
        f.native.failDeleteOnce = f.requestPath
        val maintenance = DesktopInstallInputCleanup({ Result.success(f.journal.recoverAll()) },
            release = { _, _ -> error("No receipt") }, releaseNotStarted = f.cleanup::release)
        maintenance.releaseCurrentOwnerNotStarted = true
        assertTrue(maintenance.reconcile(f.correlation.controllerId).isFailure)
        assertEquals(ControlCode.PERSISTENCE_FAILED, maintenance.decorate(f.journal.recoverAll()).single().cleanupCode)
        assertEquals(ControlCode.CANCELLED, maintenance.decorate(f.journal.recoverAll()).single().code)
        assertFalse(f.native.nodes.containsKey(f.packagePath))
        assertTrue(f.native.nodes.containsKey(f.requestPath))
        maintenance.reconcile(f.correlation.controllerId).getOrThrow()
        assertEquals(ControlCode.OK, maintenance.decorate(f.journal.recoverAll()).single().cleanupCode)
        assertFalse(f.native.nodes.containsKey(f.inputPath)); assertEquals(before, f.journalBytes())
        f.native.assertClosed()
    }

    @Test fun newForeignChildAfterValidationIsNeverRecursivelyDeleted() = fixture { f ->
        f.deny()
        val foreign = f.inputPath + "\\foreign"
        f.native.beforeDelete = { path -> if (path == f.packagePath) f.native.put(foreign, false, byteArrayOf(42)) }
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertTrue(f.native.nodes.containsKey(foreign))
        assertFalse(f.native.deletions.contains(foreign))
        assertTrue(f.native.nodes.containsKey(f.inputPath))
        f.native.assertClosed()
    }

    @Test fun originalInputIdentityWitnessCannotAuthorizeReplacementAfterPartialDeletion() = fixture { f ->
        f.deny(); f.native.failDeleteOnce = f.requestPath
        assertTrue(f.cleanup.release(f.record()).isFailure)
        f.native.put(f.packagePath, false, f.packageBytes.copyOf()) // Same digest, different native object.
        val deleted = f.native.deletions.toList()
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertEquals(deleted, f.native.deletions)
        assertTrue(f.native.nodes.containsKey(f.packagePath))
        f.native.assertClosed()
    }

    @Test fun finalCloseFailureNeverBecomesCleanupSuccessAndLaterCloseIsOwned() = fixture { f ->
        f.deny(); f.native.failClosePath = f.inputPath; f.native.failCloseCount = 3
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertTrue(f.cleanup.blocksPreparation())
        assertEquals(3, f.native.closeAttempts.count { it == f.inputPath }, "Direct, group and final capability closes all failed")
        assertTrue(f.native.handles.any { !it.closed })
        f.native.failCloseCount = 0
        f.cleanup.release(f.record()).getOrThrow()
        assertFalse(f.cleanup.blocksPreparation())
        f.native.assertClosed()
    }

    @Test fun wholeInputAbsenceIsIdempotentButInaccessibleObjectIsNotAbsence() = fixture { f ->
        f.deny(); f.cleanup.release(f.record()).getOrThrow()
        f.cleanup.release(f.record()).getOrThrow()
        assertTrue(f.cleanup.inputAbsent(f.binding))
        f.native.openFailurePath = f.inputPath; f.native.openFailureCode = 5
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertFalse(f.cleanup.inputAbsent(f.binding))
        f.native.assertClosed()
    }

    @Test fun presentNoStartInputBindingsAreNotPrunedAndCapacityBlocksNewAdmission() = fixture { f ->
        // Existing32 history limit must never discard a retained input's cleanup identity.
        f.fillRetainedJournal(); f.deny()
        assertEquals(256, f.journal.records().size, "Frozen pruning drops retained no-start bindings")
        val error = assertFailsWith<IllegalArgumentException> {
            f.journal.record(DesktopInstallCorrelation("overflow", "request", "operation"), UUID(0, 9999).toString())
        }
        assertEquals("BUSY", error.message)
        f.native.assertClosed()
    }


    @Test fun actualPreparationRejectsFullRetainedJournalBeforeHelperOrStaging() = runBlocking {
        fixture { f ->
            f.fillRetainedJournal(); f.deny()
            val packageFile = f.workspace.resolve("download.msi")
            Files.write(packageFile, f.packageBytes)
            var admittedHelper = 0
            var stagingEntered = 0
            val installer = DesktopWindowsInstaller(f.workspace, f.journal, f.cleanup,
                retainHelper = { admittedHelper++; f.helper {} },
                inputLocalAppData = { stagingEntered++; error("Unexpected input staging") })
            val result = installer.prepare(packageFile, f.asset(), "C:\\vpn-control.exe",
                DesktopInstallCorrelation("new-owner", "new-request", "new-operation"))
            assertTrue(result.isFailure)
            assertEquals("BUSY", result.exceptionOrNull()?.message)
            assertEquals(0, admittedHelper, "Full admission must precede the actual prepare helper/staging path")
            assertEquals(0, stagingEntered)
            assertEquals(256, f.journal.records().size)
            assertEquals(f.packageBytes.toList(), Files.readAllBytes(packageFile).toList())
            f.native.assertClosed()
        }
    }

    @Test fun cachedSuccessfulCleanupStillRetriesHolderDebtCreatedByJournalPruning() = runBlocking {
        fixture { f ->
            f.deny()
            var state = MainUiState()
            val installer = DesktopWindowsInstaller(f.workspace, f.journal, f.cleanup)
            val service = DesktopUpdateService({ state }, { state = it(state) }, f.workspace.resolve("updates"),
                osName = "Windows", workspaceDirectory = f.workspace, windowsInstallerFactory = { installer })
            service.reconcileTerminalInstallInputs(f.correlation.controllerId).getOrThrow()
            assertEquals(ControlCode.OK, service.recoverInstallCorrelations().getOrThrow().single().cleanupCode)
            assertFalse(f.native.nodes.containsKey(f.inputPath))
            f.native.failClosePath = f.root; f.native.failCloseCount = 2
            f.journal.record(DesktopInstallCorrelation("other", "request", "operation"), UUID(0, 9000).toString())
            // The root probe created debt after the last successful per-record cleanup.
            assertTrue(f.cleanup.blocksPreparation())
            service.reconcileTerminalInstallInputs(f.correlation.controllerId).getOrThrow()
            assertFalse(f.cleanup.blocksPreparation(), "Cached cleanupCode=OK must not skip independent holder maintenance")
            assertEquals(ControlCode.OK, service.recoverInstallCorrelations().getOrThrow()
                .single { it.binding == f.binding }.cleanupCode)
            f.native.assertClosed()
        }
    }

    @Test fun wholeAbsentBindingCannotPruneWhileUncertainHolderRemains() = fixture { f ->
        f.deny(); f.cleanup.release(f.record()).getOrThrow()
        f.native.failClosePath = f.root; f.native.failCloseCount = 2
        f.journal.record(DesktopInstallCorrelation("other", "request", "operation"), UUID(0, 9000).toString())
        assertTrue(f.cleanup.blocksPreparation())
        val opened = f.native.handles.size
        assertFalse(f.cleanup.inputAbsent(f.binding), "Whole input absence cannot erase an unresolved holder binding")
        assertEquals(opened, f.native.handles.size, "A pruning probe must not acquire more handles while debt remains")
        f.native.failCloseCount = 0
        f.cleanup.reconcileHolders().getOrThrow()
        assertTrue(f.cleanup.inputAbsent(f.binding))
        f.native.assertClosed()
    }

    @Test fun actualPreparationStopsBeforeStagingWhenFinalRecordProbeCreatesHolderDebt() = runBlocking {
        fixture { f ->
            f.deny(); f.cleanup.release(f.record()).getOrThrow()
            var helperClosed = false
            var stagingEntered = 0
            val packageFile = f.workspace.resolve("download.msi")
            Files.write(packageFile, f.packageBytes)
            val correlation = DesktopInstallCorrelation("new-owner", "new-request", "new-operation")
            val installer = DesktopWindowsInstaller(f.workspace, f.journal, f.cleanup,
                retainHelper = {
                    // requireNew() has completed. Fail the root probe inside the final record().
                    f.native.failClosePath = f.root; f.native.failCloseCount = 4
                    f.helper { helperClosed = true }
                }, inputLocalAppData = { stagingEntered++; error("Unexpected input staging") })
            val result = installer.prepare(packageFile, f.asset(), "C:\\vpn-control.exe", correlation)
            assertTrue(result.isFailure)
            assertEquals(0, stagingEntered, "An inspection-created failed holder must stop the current preparation")
            assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
            assertTrue(helperClosed, "All admitted holders must receive a close attempt")
            val recovered = f.journal.recover(correlation)
            assertTrue(recovered.notStarted)
            assertEquals(ControlCode.CANCELLED, recovered.code)
            assertNotNull(recovered.binding, "The failed attempt keeps a durable retry/history binding")
            f.native.failCloseCount = 0
            installer.reconcileInputHolders().getOrThrow()
            assertFalse(f.cleanup.blocksPreparation())
            f.native.assertClosed()
        }
    }

    @Test fun arbitraryPrelaunchAndTransientCloseFailuresKeepEveryCapabilityOwned() = fixture { f ->
        // This is the same acquisition facade used by preparation's temporary write,
        // publication, package output and transfer-pin construction handles.
        val handles = DesktopWindowsDeniedInputHandles(f.native)
        val first = handles.native.open(f.root, WindowsInstallNative.INSPECT, false)
        val second = handles.native.open(f.inputPath, WindowsInstallNative.INSPECT, false)
        f.native.failClosePath = f.root; f.native.failCloseCount = 3
        assertFails { handles.native.close(first) } // A transient finally-close fails.
        handles.native.close(second)
        handles.native.close(second) // An enclosing pin group can safely retry successful closes.
        val owned = mutableListOf<AutoCloseable>(handles)
        assertTrue(f.cleanup.retainUncertainHolders(owned).isFailure)
        assertTrue(owned.isEmpty(), "Failed fallback close transfers ownership instead of losing the local list")
        assertTrue(f.cleanup.blocksPreparation())
        assertFalse(f.cleanup.inputAbsent(f.binding))
        f.native.failCloseCount = 0
        f.cleanup.reconcileHolders().getOrThrow()
        assertFalse(f.cleanup.blocksPreparation())
        assertTrue(f.native.deletions.isEmpty(), "An arbitrary failure never grants input disposal")
        f.native.assertClosed()
    }

    @Test fun actualPreparationAdoptsFailedAdmissionCarrierAndPreservesOriginalCause() = runBlocking {
        fixture { f ->
            f.deny(); f.cleanup.release(f.record()).getOrThrow()
            val original = IllegalStateException("PERMISSION_DENIED")
            var attempts = 0
            var stagingEntered = 0
            val retained = AutoCloseable { attempts++; if (attempts <= 2) error("native close failure") }
            val carrier = DesktopWindowsAdmissionCleanupFailure(original, retained)
            val installer = DesktopWindowsInstaller(f.workspace, f.journal, f.cleanup,
                retainHelper = { throw carrier },
                inputLocalAppData = { stagingEntered++; error("Unexpected input staging") })
            val packageFile = f.workspace.resolve("download.msi")
            Files.write(packageFile, f.packageBytes)
            val result = installer.prepare(packageFile, f.asset(), "C:\\vpn-control.exe",
                DesktopInstallCorrelation("new-owner", "new-request", "new-operation"))
            assertEquals(1, attempts, "Admission failure before lease return must still attempt its retained capability")
            assertEquals(0, stagingEntered)
            assertTrue(result.isFailure)
            val failure = result.exceptionOrNull()!!
            assertEquals("PERSISTENCE_FAILED", failure.message)
            assertSame(carrier, failure.cause)
            assertSame(original, (failure.cause as DesktopWindowsAdmissionCleanupFailure).originalFailure)
            assertEquals(1, failure.suppressed.size, "Cleanup failure cannot replace or erase the original admission cause")
            assertTrue(f.cleanup.blocksPreparation())
            assertEquals(1, f.journal.records().size, "The failed helper cannot create staged input or a new launch identity")
            assertTrue(installer.reconcileInputHolders().isFailure)
            assertEquals(2, attempts)
            assertTrue(f.cleanup.blocksPreparation())
            installer.reconcileInputHolders().getOrThrow()
            assertEquals(3, attempts)
            assertFalse(f.cleanup.blocksPreparation())
            assertTrue(f.native.deletions.count { it == f.inputPath } == 1)
            f.native.assertClosed()
        }
    }

    private inline fun fixture(block: (WindowsDeniedInputFixture) -> Unit) {
        val fixture = WindowsDeniedInputFixture()
        try { block(fixture) } finally { fixture.close() }
    }
}

private class WindowsDeniedInputFixture : AutoCloseable {
    val workspace: Path = Files.createTempDirectory("windows-denied-input-").toRealPath()
    val sid = "S-1-5-21-1-2-3-1001"
    val root = "C:\\Users\\Test\\AppData\\Local\\vpn-control-install-inputs"
    val job = "00000000-0000-0000-0000-000000000081"
    val inputPath = root + "\\" + job
    val packagePath = inputPath + "\\package.msi"
    val requestPath = inputPath + "\\request.json"
    val correlation = DesktopInstallCorrelation("original-owner", "original-request", "original-operation")
    val native = DeniedInputFileModel(sid)
    var protectedPresent = false
    var protectedInaccessible = false
    var pending = false
    private fun readProtected(id: String): DesktopInstallJobReceipt {
        if (protectedInaccessible) throw WindowsInstallNativeFailure(5)
        if (!protectedPresent) throw WindowsInstallNativeFailure(2)
        return DesktopInstallJobReceipt(id, 1, DesktopInstallJobPhase.INSTALLING, ControlCode.ACCEPTED)
    }
    lateinit var cleanup: DesktopWindowsDeniedInputCleanup
    val journal = DesktopInstallCorrelationJournal(workspace,
        canPruneTerminal = { record -> !record.notStarted || cleanup.inputAbsent(record.binding!!) },
        readProtectedReceipt = ::readProtected)
    val packageBytes = ByteArray(20001) { (it % 251 + 1).toByte() }
    val request = DesktopWindowsInstallRequest(job, sid, 2344, 1791604564314,
        "C:\\Users\\Test\\vpn-control.exe", packagePath, DesktopWindowsDeniedInputCleanup.sha(packageBytes),
        packageBytes.size.toLong(), "C:\\workspace")
    val binding: DesktopInstallCorrelationRecord
    val witness: DesktopWindowsDeniedInputWitness
    init {
        var path = "C:\\"
        native.put(path, true)
        for (name in root.substring(3).split('\\')) { path = path.trimEnd('\\') + "\\" + name; native.put(path, true) }
        native.put(inputPath, true); native.put(packagePath, false, packageBytes.copyOf()); native.put(requestPath, false, request.encode())
        val paths = object : WindowsAdmissionNative by JnaWindowsInstallAdmission() {
            override fun currentSid() = sid
            override fun canonicalPath(handle: WindowsInstallNative.Handle) = native.deniedInputCanonicalPath(handle)
            override fun children(path: String) = native.deniedInputChildren(path)
        }
        cleanup = DesktopWindowsDeniedInputCleanup(root, "C:\\workspace", native, paths,
            read = { journal.recover(it.correlation) }, requireProtectedAbsent = {
                journal.requireReceiptAbsent(it.correlation, it.jobId)
                if (protectedPresent) error("OUTCOME_UNKNOWN")
            }, hasPending = { pending })
        binding = journal.record(correlation, job)
        witness = DesktopWindowsDeniedInputWitness(binding, request, native.nodes.getValue(root).identity,
            native.nodes.getValue(inputPath).identity, native.nodes.getValue(requestPath).identity,
            native.nodes.getValue(packagePath).identity, DesktopWindowsDeniedInputCleanup.sha(request.encode()))
    }
    fun fillRetainedJournal() {
        // Publish all unknown bindings first, then real no-start markers. This exercises the
        // production codecs and guard without cubic repeated terminal inspection during setup.
        val bindings = (1..255).map { number ->
            val correlation = DesktopInstallCorrelation("other-$number", "request-$number", "operation-$number")
            val job = UUID(0, number.toLong() + 1000).toString()
            native.put(root + "\\" + job, true)
            journal.record(correlation, job)
        }
        for (binding in bindings) journal.markNotStarted(binding.correlation, binding.jobId)
    }
    fun asset() = UpdateAsset(UpdatePlatform.WINDOWS, "x64", UpdatePackageType.MSI, "2.2.4",
        "package.msi", "https://invalid.example/package.msi", request.packageSha256, packageBytes.size.toLong())
    fun helper(onClose: () -> Unit): DesktopWindowsInstallHelperLease = object : DesktopWindowsInstallHelperLease {
        override val executable = "C:\\vpn-control-install-helper.exe"
        override val owner = DesktopWindowsRuntimeResourceNativeOwner(ProcessHandle.current().pid(), 1, sid)
        override fun parameters(jobId: String): String = error("No coordinator launch is authorized in this control")
        override fun verifyStartedProcess(process: WinNT.HANDLE): Unit = error("No process was started")
        override fun close() = onClose()
    }
    fun deny() { journal.markNotStarted(correlation, job); cleanup.retainNativeDenial(witness, 1223, mutableListOf()).getOrThrow() }
    fun record() = journal.recover(correlation)
    fun journalBytes() = Files.list(workspace).use { paths -> paths.toList().associate { it.fileName.toString() to Files.readString(it) } }
    override fun close() { Files.walk(workspace).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } } }
}

/** Explicit Windows sharing/delete-pending state; every assertion measures production decisions. */
private class DeniedInputFileModel(private val sid: String) : WindowsDeniedInputNative {
    class Node(var info: WindowsInstallInfo, var bytes: ByteArray, var identity: String,
        var persistentAcl: Boolean = true, var deletePending: Boolean = false)
    class Handle(val path: String, val node: Node, val rights: Int, val share: Int) : WindowsInstallNative.Handle { var closed = false }
    val nodes = linkedMapOf<String, Node>()
    val handles = mutableListOf<Handle>()
    val deletions = mutableListOf<String>()
    val closeAttempts = mutableListOf<String>()
    var serial = 0L
    var failDeleteOnce: String? = null
    var failClosePath: String? = null
    var failCloseCount = 0
    var openFailurePath: String? = null
    var openFailureCode = 5
    var beforeDelete: ((String) -> Unit)? = null
    fun put(path: String, directory: Boolean, bytes: ByteArray = byteArrayOf()) {
        nodes[path] = Node(WindowsInstallInfo(directory, owner = sid,
            dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, sid), WindowsInstallAce(0, 0, 0x120089, "S-1-5-32-544"))),
            bytes, (++serial).toString(16).padStart(48, '0'))
    }
    override fun programData() = "C:\\ProgramData"
    override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) = error("Not a disposal primitive")
    override fun writeAndSync(handle: WindowsInstallNative.Handle, bytes: ByteArray) = error("Disposal must not rewrite inputs")
    override fun rename(handle: WindowsInstallNative.Handle, directory: WindowsInstallNative.Handle, name: String) = error("Disposal must not publish")
    override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?): WindowsInstallNative.Handle {
        require(createSddl == null)
        val options = windowsInstallOpenOptions(access, shareDelete, false)
        return openExact(path, options.rights, options.share)
    }
    override fun openDeniedInput(path: String) = openExact(path, 0x00130081, 1)
    private fun openExact(path: String, rights: Int, share: Int): WindowsInstallNative.Handle {
        if (path == openFailurePath) throw WindowsInstallNativeFailure(openFailureCode)
        val node = nodes[path] ?: throw WindowsInstallNativeFailure(2)
        if (node.deletePending) throw WindowsInstallNativeFailure(5)
        for (old in handles.filter { !it.closed && it.node === node }) {
            if (rights and 1 != 0 && old.share and 1 == 0 || old.rights and 1 != 0 && share and 1 == 0 ||
                rights and 2 != 0 && old.share and 2 == 0 || old.rights and 2 != 0 && share and 2 == 0 ||
                rights and 0x10000 != 0 && old.share and 4 == 0 || old.rights and 0x10000 != 0 && share and 4 == 0)
                throw WindowsInstallNativeFailure(32)
        }
        return Handle(path, node, rights, share).also { handles += it }
    }
    override fun inspect(handle: WindowsInstallNative.Handle) = opened(handle).node.let { it.info.copy(size = it.bytes.size.toLong()) }
    override fun deniedInputIdentity(handle: WindowsInstallNative.Handle) = opened(handle).node.identity
    override fun deniedInputCanonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + opened(handle).path
    override fun deniedInputPersistentAcl(handle: WindowsInstallNative.Handle) = opened(handle).node.persistentAcl
    override fun deniedInputChildren(path: String) = nodes.keys.filter { it.substringBeforeLast('\\') == path }.take(3).map { it.substringAfterLast('\\') }
    override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray {
        val file = opened(handle); require(file.rights and 1 != 0); return file.node.bytes.take(limit).toByteArray()
    }
    override fun readDeniedInputChunk(handle: WindowsInstallNative.Handle, offset: Long, bytes: ByteArray, count: Int): Int {
        require(count in 1..8192)
        val file = opened(handle); require(file.rights and 1 != 0)
        val size = minOf(count, (file.node.bytes.size.toLong() - offset).coerceAtLeast(0).toInt())
        file.node.bytes.copyInto(bytes, 0, offset.toInt(), offset.toInt() + size); return size
    }
    override fun delete(handle: WindowsInstallNative.Handle) {
        val file = opened(handle); require(file.rights and 0x10000 != 0)
        beforeDelete?.invoke(file.path)
        if (file.path == failDeleteOnce) { failDeleteOnce = null; throw WindowsInstallNativeFailure(5) }
        if (file.node.info.directory && nodes.keys.any { it.substringBeforeLast('\\') == file.path }) throw WindowsInstallNativeFailure(145)
        file.node.deletePending = true; deletions += file.path
    }
    override fun close(handle: WindowsInstallNative.Handle) {
        val file = opened(handle)
        closeAttempts += file.path
        if (file.path == failClosePath && failCloseCount > 0) { failCloseCount--; throw WindowsInstallNativeFailure(6) }
        file.closed = true
        if (file.node.deletePending && handles.none { !it.closed && it.node === file.node }) nodes.remove(file.path)
    }
    private fun opened(handle: WindowsInstallNative.Handle) = (handle as Handle).also { check(!it.closed) }
    fun assertClosed() { assertTrue(handles.all { it.closed }, "Leaked: ${handles.filter { !it.closed }.map { it.path }}") }
}
