package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

/** Real journal/receipt/custody codecs and TempFS streams. Only Windows syscalls/namespace/ACLs are modeled. */
class DesktopWindowsCompletedInputCleanupTest {
    @Test fun successfulOwnerMaintenanceDeletesExactInputsAndPreservesProtectedHistory() = fixture { f ->
        val before = f.journalBytes()
        val protected = f.protectedBytes()
        val installer = DesktopWindowsInstaller(f.workspace, correlationsOverride = f.journal, completedInputCleanupOverride = f.cleanup)
        val maintenance = DesktopInstallInputCleanup({ Result.success(f.journal.recoverAll()) }, installer::releaseCompleted)
        maintenance.reconcile("replacement-owner").getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.input), "Authentic old releaseCompleted reports OK while five inputs remain")
        assertEquals(ControlCode.OK, maintenance.decorate(f.journal.recoverAll()).single().cleanupCode)
        assertEquals(before, f.journalBytes())
        assertEquals(protected, f.protectedBytes())
        f.native.assertClosed()
    }
    @Test fun coldRecoveryUsesNativeCustodyAndFullBytesWithoutLaunching() = fixture { f ->
        f.cleanup.release(f.record()).getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.input))
        assertEquals(6, f.native.deletions.size)
        assertTrue(f.cleanup.inputAbsent(f.binding))
        assertEquals(DesktopInstallJobPhase.SUCCEEDED, f.record().receipt?.phase)
    }
    @Test fun legacyPresentInputsCannotReportCleanupOk() = fixture { f ->
        f.native.nodes.remove(f.protectedJob + "\\input-custody.json")
        val installer = DesktopWindowsInstaller(f.workspace, correlationsOverride = f.journal, completedInputCleanupOverride = f.cleanup)
        val maintenance = DesktopInstallInputCleanup({ Result.success(f.journal.recoverAll()) }, installer::releaseCompleted)
        assertTrue(maintenance.reconcile("replacement-owner").isFailure)
        assertEquals(ControlCode.PERSISTENCE_FAILED, maintenance.decorate(f.journal.recoverAll()).single().cleanupCode)
        assertEquals(DesktopInstallJobPhase.SUCCEEDED, f.record().receipt?.phase)
        assertTrue(f.native.deletions.isEmpty())
    }
    @Test fun liveUnknownForeignAndUninspectableJobsNeverDelete() {
        val changes: List<(CompletedInputFixture) -> DesktopInstallCorrelationRecovery> = listOf(
            { it.pending = true; it.record() },
            { it.native.actor = CompletedInputFileModel.Actor.LIVE; it.record() },
            { it.native.actor = CompletedInputFileModel.Actor.UNINSPECTABLE; it.record() },
            { it.receipt = DesktopInstallJobReceipt(it.job, 3, DesktopInstallJobPhase.INSTALLING, ControlCode.OK); it.publishReceipt(); it.record() },
            { it.record().copy(binding = it.binding.copy(workspaceKey = "f".repeat(64))) },
            { it.record().copy(binding = it.binding.copy(receiptAuthority = DesktopInstallReceiptAuthority.MACOS_USER_LOCAL)) },
            { it.record().copy(receipt = it.receipt.copy(sequence = 99)) },
        )
        for ((index, change) in changes.withIndex()) fixture { f ->
            assertTrue(f.cleanup.release(change(f)).isFailure, "change $index")
            assertTrue(f.native.deletions.isEmpty(), "change $index")
        }
    }
    @Test fun allIdentityAclContentAndPopulationGuardsRejectBeforeDelete() {
        val changes: List<(CompletedInputFixture) -> Unit> = listOf(
            { it.native.nodes.getValue(it.root).identity = "f".repeat(48) },
            { it.native.nodes.getValue(it.input).identity = "f".repeat(48) },
            { it.native.nodes.getValue(it.input + "\\package.msi").identity = "f".repeat(48) },
            { it.native.nodes.getValue(it.input + "\\request.json").bytes = byteArrayOf(1) },
            { it.native.nodes.getValue(it.input + "\\package.msi").bytes[0] = 0; it.native.nodes.getValue(it.input + "\\package.msi").bytes = byteArrayOf(0) },
            { it.native.nodes.getValue(it.input).info = it.native.nodes.getValue(it.input).info.copy(reparseTag = 1) },
            { it.native.nodes.getValue(it.input + "\\commit.json").info = it.native.nodes.getValue(it.input + "\\commit.json").info.copy(links = 2) },
            { it.native.nodes.getValue(it.input + "\\commit.json").info = it.native.nodes.getValue(it.input + "\\commit.json").info.copy(owner = "S-1-5-21-9-9-9-999") },
            { it.native.nodes.getValue(it.input).persistentAcl = false },
            { it.native.nodes.getValue(it.input).protectedDacl = false },
            { it.native.nodes.getValue(it.input).info = it.native.nodes.getValue(it.input).info.copy(dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, "S-1-5-32-544"))) },
            { it.native.put(it.input + "\\foreign", false, byteArrayOf(1)) },
            { it.native.nodes.getValue(it.protectedJob).identity = "f".repeat(48) },
            { it.native.nodes.getValue(it.protectedJob + "\\input-custody.json").bytes = byteArrayOf(1) },
            { it.native.nodes.getValue(it.protectedJob + "\\input-custody.json").info = it.native.nodes.getValue(it.protectedJob + "\\input-custody.json").info.copy(owner = it.sid) },
        )
        for ((index, change) in changes.withIndex()) fixture { f ->
            change(f)
            assertTrue(f.cleanup.release(f.record()).isFailure, "mutation $index")
            assertTrue(f.native.deletions.isEmpty(), "mutation $index")
        }
    }
    @Test fun partialDeleteRetriesOnlyExactRemainingInputsAndRejectsReplacement() = fixture { f ->
        f.native.failDeleteOnce = f.input + "\\commit.json"
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertFalse(f.native.nodes.containsKey(f.input + "\\package.msi"))
        f.cleanup.release(f.record()).getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.input))
        assertEquals(6, f.native.deletions.size)
    }
    @Test fun sameBytesForeignReplacementAfterPartialDeleteIsRefused() = fixture { f ->
        f.native.failDeleteOnce = f.input + "\\commit.json"
        assertTrue(f.cleanup.release(f.record()).isFailure)
        val path = f.input + "\\commit.json"; val bytes = f.native.nodes.getValue(path).bytes
        f.native.put(path, false, bytes)
        val count = f.native.deletions.size
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertEquals(count, f.native.deletions.size)
    }
    @Test fun lateForeignChildSurvivesAndBlocksFalseOk() = fixture { f ->
        f.native.beforeDelete = { path -> if (path == f.input) { f.native.beforeDelete = null; f.native.put(f.input + "\\foreign", false, byteArrayOf(3)) } }
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertTrue(f.native.nodes.containsKey(f.input + "\\foreign"))
        assertFalse(f.cleanup.inputAbsent(f.binding))
    }
    @Test fun failedCloseRetainsDebtAndAllOtherReleasesAreAttempted() = fixture { f ->
        f.native.failClosePath = f.input + "\\package.msi"; f.native.failCloseCount = 3
        assertTrue(f.cleanup.release(f.record()).isFailure)
        assertTrue(f.cleanup.blocksPreparation())
        assertTrue(f.native.closeAttempts.any { it.endsWith("worker-result.json") })
        f.cleanup.reconcileHolders().getOrThrow()
        assertFalse(f.cleanup.blocksPreparation())
        f.cleanup.release(f.record()).getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.input))
    }
    @Test fun inaccessibleAncestorIsNotAbsenceAndReusedPidIsNeverTerminated() = fixture { f ->
        f.native.openFailurePath = f.root.substringBeforeLast('\\'); f.native.openFailureCode = 5
        assertFalse(f.cleanup.inputAbsent(f.binding))
        assertTrue(f.cleanup.release(f.record()).isFailure)
        f.native.openFailurePath = null; f.native.actor = CompletedInputFileModel.Actor.REUSED
        f.cleanup.release(f.record()).getOrThrow()
        assertFalse(f.native.nodes.containsKey(f.input))
    }
    private inline fun fixture(block: (CompletedInputFixture) -> Unit) {
        val f = CompletedInputFixture(); try { block(f) } finally { f.close() }
    }
}

private class CompletedInputFixture : AutoCloseable {
    val workspace = Files.createTempDirectory("completed-input-journal-").toRealPath()
    val sid = "S-1-5-21-1-2-3-1001"
    val root = "C:\\Users\\Test\\AppData\\Local\\vpn-control-install-inputs"
    val job = "00000000-0000-0000-0000-000000000082"
    val input = root + "\\" + job
    val protectedRoot = "C:\\ProgramData\\vpn-control-install-jobs"
    val protectedJob = protectedRoot + "\\" + job
    val native = CompletedInputFileModel(sid)
    val correlation = DesktopInstallCorrelation("original-owner", "original-request", "original-operation")
    var receipt = DesktopInstallJobReceipt(job, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
    var pending = false
    val ancestry = object : WindowsAdmissionNative by JnaWindowsInstallAdmission() {
        override fun currentSid() = sid
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = native.deniedInputCanonicalPath(handle)
        override fun children(path: String) = native.nodes.keys.filter { it.substringBeforeLast('\\') == path }.map { it.substringAfterLast('\\') }
    }
    val store = DesktopInstallJobStore(DesktopWindowsInstallJobBackend(native, ancestry), Path.of(protectedRoot))
    val journal = DesktopInstallCorrelationJournal(workspace, readProtectedReceipt = { id -> store.open(id).use { it.read() } })
    val binding: DesktopInstallCorrelationRecord
    val cleanup: DesktopWindowsCompletedInputCleanup
    init {
        fun dirs(path: String, protected: Boolean) {
            var prefix = "C:\\"
            if (prefix !in native.nodes) native.put(prefix, true)
            for (part in path.substring(3).split('\\')) { prefix = prefix.trimEnd('\\') + "\\" + part; if (prefix !in native.nodes) native.put(prefix, true) }
            if (protected) for ((name, node) in native.nodes) if (name == "C:\\" || name.startsWith("C:\\ProgramData")) {
                node.info = node.info.copy(owner = "S-1-5-32-544", dacl = listOf(WindowsInstallAce(0,0,0x1f01ff,"S-1-5-32-544"), WindowsInstallAce(0,0,0x120089,"S-1-5-32-545")))
            }
        }
        dirs(input, false); dirs(protectedJob, true)
        binding = journal.record(correlation, job)
        val names = listOf("request.json","package.msi","commit.json","worker-ready.json","worker-result.json")
        for ((index, name) in names.withIndex()) native.put(input + "\\" + name, false, ByteArray(if (index == 1) 20001 else 50 + index) { ((it + index) % 251 + 1).toByte() })
        val values = linkedMapOf<String, ControlValue>("version" to ControlValue.IntegerValue(1), "jobId" to ControlValue.Text(job),
            "principalSid" to ControlValue.Text(sid), "workspaceSha256" to ControlValue.Text(binding.workspaceKey),
            "inputRootNativeId" to ControlValue.Text(native.nodes.getValue(root).identity), "inputJobNativeId" to ControlValue.Text(native.nodes.getValue(input).identity),
            "protectedMachineNativeId" to ControlValue.Text(native.nodes.getValue(protectedRoot).identity), "protectedJobNativeId" to ControlValue.Text(native.nodes.getValue(protectedJob).identity),
            "workerPid" to ControlValue.IntegerValue(300), "workerCreationFileTime" to ControlValue.IntegerValue(1), "workerHelperSha256" to ControlValue.Text("a".repeat(64)),
            "coordinatorPid" to ControlValue.IntegerValue(301), "coordinatorCreationFileTime" to ControlValue.IntegerValue(2), "coordinatorHelperSha256" to ControlValue.Text("a".repeat(64)))
        for (name in names) {
            val node = native.nodes.getValue(input + "\\" + name)
            values[name + ".nativeId"] = ControlValue.Text(node.identity)
            values[name + ".size"] = ControlValue.IntegerValue(node.bytes.size.toLong())
            values[name + ".sha256"] = ControlValue.Text(DesktopWindowsDeniedInputCleanup.sha(node.bytes))
        }
        fun protectedFile(name: String, bytes: ByteArray) {
            val path = protectedJob + "\\" + name; native.put(path, false, bytes)
            native.nodes.getValue(path).info = native.nodes.getValue(path).info.copy(owner="S-1-5-32-544", dacl=listOf(WindowsInstallAce(0,0,0x1f01ff,"S-1-5-32-544"),WindowsInstallAce(0,0,0x120089,"S-1-5-32-545")))
        }
        protectedFile("input-custody.json", ControlProtocolCodec.encodeValues(values).encodeToByteArray())
        protectedFile("status.json", receipt.encode())
        cleanup = DesktopWindowsCompletedInputCleanup(root, native, ancestry, { journal.recover(it.correlation) }, { pending })
    }
    fun publishReceipt() { native.nodes.getValue(protectedJob + "\\status.json").bytes = receipt.encode() }
    fun record() = journal.recover(correlation)
    fun journalBytes() = Files.list(workspace).use { it.toList().associate { path -> path.fileName.toString() to Files.readString(path) } }
    fun protectedBytes() = native.nodes.filterKeys { it.startsWith(protectedJob + "\\") }.mapValues { it.value.bytes.toList() }
    override fun close() { cleanup.reconcileHolders().getOrThrow(); native.dispose(); Files.walk(workspace).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
}

private class CompletedInputFileModel(private val sid: String) : WindowsCompletedInputNative {
    class Node(var info: WindowsInstallInfo, val file: Path, var identity: String,
        var persistentAcl: Boolean = true, var deletePending: Boolean = false, var protectedDacl: Boolean = true) {
        var bytes: ByteArray
            get() = if (info.directory) byteArrayOf() else Files.readAllBytes(file)
            set(value) { Files.write(file, value) }
    }
    class Handle(val path: String, val node: Node, val rights: Int, val share: Int) : WindowsInstallNative.Handle { var closed = false; var stream: java.io.InputStream? = if (node.info.directory) null else Files.newInputStream(node.file) }
    val temp = Files.createTempDirectory("completed-native-inert-")
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
            temp.resolve((++serial).toString()).also { if (directory) Files.createDirectory(it) else Files.write(it, bytes) }, serial.toString(16).padStart(48, '0'))
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
        if (file.path == failClosePath && failCloseCount > 0 && file.rights and 0x10000 != 0 && file.node.deletePending) { failCloseCount--; throw WindowsInstallNativeFailure(6) }
        file.stream?.close(); file.closed = true
        if (file.node.deletePending && handles.none { !it.closed && it.node === file.node }) { nodes.remove(file.path); Files.delete(file.node.file) }
    }
    enum class Actor { CLOSED, LIVE, REUSED, UNINSPECTABLE }
    var actor = Actor.CLOSED
    var actorHandles = 0
    override fun completedInputChildren(path: String) = nodes.keys.filter { it.substringBeforeLast('\\') == path }.take(6).map { it.substringAfterLast('\\') }
    override fun completedInputProtectedDacl(handle: WindowsInstallNative.Handle) = opened(handle).node.protectedDacl
    override fun openInputActor(pid: Long): WindowsCompletedInputActor {
        if (actor == Actor.UNINSPECTABLE) throw WindowsInstallNativeFailure(5)
        actorHandles++
        return object : WindowsCompletedInputActor {
            var closed = false
            override fun requireOriginalClosed(creationFileTime: Long) { check(!closed); if (actor == Actor.LIVE) error("OUTCOME_UNKNOWN") }
            override fun close() { if (!closed) { closed = true; actorHandles-- } }
        }
    }
    fun dispose() { assertClosed(); assertEquals(0, actorHandles); Files.walk(temp).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    private fun opened(handle: WindowsInstallNative.Handle) = (handle as Handle).also { check(!it.closed) }
    fun assertClosed() { assertTrue(handles.all { it.closed }, "Leaked: ${handles.filter { !it.closed }.map { it.path }}") }
}
