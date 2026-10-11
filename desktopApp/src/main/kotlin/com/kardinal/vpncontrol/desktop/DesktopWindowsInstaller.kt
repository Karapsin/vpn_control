package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.model.ControlCode
import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.PointerByReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID

/** Creates private immutable input and launches the admitted packaged native coordinator. */
internal class DesktopWindowsInstaller(
    private val workspaceDirectory: Path = DesktopWorkspacePaths.root(),
    correlationsOverride: DesktopInstallCorrelationJournal? = null,
    deniedInputCleanupOverride: DesktopWindowsDeniedInputCleanup? = null,
    completedInputCleanupOverride: DesktopWindowsCompletedInputCleanup? = null,
    private val retainHelper: () -> DesktopWindowsInstallHelperLease = { DesktopWindowsInstallHelperAdmission.retain() },
    private val inputLocalAppData: (() -> String)? = null,
) {
    // Once a worker exists, even a lost authorization result must not admit an unrelated installation.
    private var pending: DesktopPreparedInstall? = null
    private val protectedInspectionHolders = mutableListOf<AutoCloseable>()
    private val correlations: DesktopInstallCorrelationJournal by lazy { correlationsOverride ?: DesktopInstallCorrelationJournal(workspaceDirectory,
        canPruneTerminal = { record -> if (record.notStarted) deniedInputCleanup.inputAbsent(requireNotNull(record.binding))
            else completedInputCleanup.inputAbsent(requireNotNull(record.binding)) }) }
    private val deniedInputCleanup: DesktopWindowsDeniedInputCleanup by lazy { deniedInputCleanupOverride ?: DesktopWindowsDeniedInputCleanup(
        localAppData() + "\\vpn-control-install-inputs", workspaceDirectory.toAbsolutePath().normalize().toString(),
        JnaWindowsInstallNative(), JnaWindowsInstallAdmission(),
        read = { binding -> correlations.recover(binding.correlation) },
        requireProtectedAbsent = { binding ->
            correlations.requireReceiptAbsent(binding.correlation, binding.jobId)
            requireProtectedJobAbsent(binding.jobId)
        }, hasPending = { pending != null }) }

    private val completedInputCleanup: DesktopWindowsCompletedInputCleanup by lazy { completedInputCleanupOverride ?:
        DesktopWindowsCompletedInputCleanup({ localAppData() + "\\vpn-control-install-inputs" }, JnaWindowsInstallNative(),
            JnaWindowsInstallAdmission(), read = { binding -> correlations.recover(binding.correlation) }, hasPending = { pending != null }) }

    fun releaseNotStarted(record: DesktopInstallCorrelationRecovery): Result<Unit> = deniedInputCleanup.release(record)

    fun reconcileInputHolders(): Result<Unit> {
        val protectedClose = closeWindowsDeniedInputHolders(protectedInspectionHolders)
        val inputClose = deniedInputCleanup.reconcileHolders()
        val completedClose = completedInputCleanup.reconcileHolders()
        return protectedClose.fold({ inputClose.fold({ completedClose }, { Result.failure(it) }) }, { Result.failure(it) })
    }

    private fun requireProtectedJobAbsent(jobId: String) {
        closeWindowsDeniedInputHolders(protectedInspectionHolders).getOrThrow()
        val nativeHandles = DesktopWindowsDeniedInputHandles(JnaWindowsInstallNative())
        protectedInspectionHolders += nativeHandles
        val backend = DesktopWindowsInstallJobBackend(native = nativeHandles.native)
        try {
            val root = try { backend.openRoot(backend.defaultRoot(), create = false) }
            catch (missing: WindowsInstallNativeFailure) {
                if (missing.code in setOf(2, 3)) return else throw missing
            }
            protectedInspectionHolders += root
            val job = try { root.openJob(jobId) }
            catch (missing: WindowsInstallNativeFailure) {
                if (missing.code in setOf(2, 3)) null else throw missing
            }
            if (job != null) {
                protectedInspectionHolders += job
                error("OUTCOME_UNKNOWN")
            }
        } finally {
            closeWindowsDeniedInputHolders(protectedInspectionHolders).getOrThrow()
        }
    }

    fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> = runCatching { correlations.recoverAll() }

    /** Release only after re-reading the exact protected terminal record; never publish cancellation. */
    fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> = runCatching {
        require(receipt.phase.terminal)
        val recovered = correlations.recoverAll().single { it.binding?.correlation == correlation }
        require(recovered.binding?.jobId == receipt.jobId && recovered.receipt == receipt)
        pending?.let { require(it.jobId == receipt.jobId); it.close() }
        pending = null
        completedInputCleanup.release(recovered).getOrThrow()
    }

    suspend fun prepare(packageFile: Path, asset: UpdateAsset, launcher: String,
        correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity? = null,
        onCancellationConfirmed: () -> Unit = {},
    ): Result<DesktopPreparedInstall> = withContext(Dispatchers.IO) {
        if (pending != null || protectedInspectionHolders.isNotEmpty() || deniedInputCleanup.blocksPreparation() || completedInputCleanup.blocksPreparation()) return@withContext Result.failure(IllegalStateException("BUSY"))
        val native = JnaWindowsInstallNative()
        val nativeHandles = DesktopWindowsDeniedInputHandles(native)
        val pinnedNative = nativeHandles.native
        val pins = mutableListOf<AutoCloseable>(nativeHandles)
        var launched = false
        var coordinatorAttempted = false
        var coordinatorDenied = false
        var recordedJobId: String? = null
        var deniedWitness: DesktopWindowsDeniedInputWitness? = null
        var deniedNativeCode: Int? = null
        try {
            correlations.requireNew(correlation)
            check(protectedInspectionHolders.isEmpty() && !deniedInputCleanup.blocksPreparation() && !completedInputCleanup.blocksPreparation()) { "PERSISTENCE_FAILED" }
            val helper = retainHelper()
            pins += helper
            val sid = helper.owner.sid
            val owner = ProcessHandle.current()
            require(owner.pid() == helper.owner.processId) { "CONFLICT" }
            val started = requireNotNull(owner.info().startInstant().orElse(null)).toEpochMilli()
            val jobId = UUID.randomUUID().toString()
            // The final race-safe capacity check and durable identity also precede staging.
            val binding = correlations.record(correlation, jobId)
            recordedJobId = jobId
            check(protectedInspectionHolders.isEmpty() && !deniedInputCleanup.blocksPreparation() && !completedInputCleanup.blocksPreparation()) { "PERSISTENCE_FAILED" }
            val local = inputLocalAppData?.invoke() ?: localAppData()
            pins += DesktopWindowsTransferPins.open(local, sid, pinnedNative)
            val inputRoot = "$local\\vpn-control-install-inputs"
            val directoryAcl = "O:${sid}G:${sid}D:P(A;OICI;FA;;;$sid)(A;OICI;GRGX;;;BA)(A;OICI;GRGX;;;SY)"
            native.createDirectory(inputRoot, directoryAcl, true)
            val inputRootPins = DesktopWindowsTransferPins.open(inputRoot, sid, pinnedNative)
            pins += inputRootPins
            val inputRootIdentity = native.deniedInputIdentity(inputRootPins.parentHandle)
            val input = "$inputRoot\\$jobId"
            native.createDirectory(input, directoryAcl, false)
            val inputPins = DesktopWindowsTransferPins.open(input, sid, pinnedNative)
            pins += inputPins
            val inputIdentity = native.deniedInputIdentity(inputPins.parentHandle)
            val fileAcl = "O:${sid}G:${sid}D:P(A;;FA;;;$sid)(A;;GR;;;BA)(A;;GR;;;SY)"
            fun writeRecord(name: String, bytes: ByteArray): String {
                val temporary = "$input\\record-${UUID.randomUUID()}.tmp"
                val handle = pinnedNative.open(temporary, WindowsInstallNative.READ_WRITE, false, fileAcl)
                try { native.writeAndSync(handle, bytes) } finally { pinnedNative.close(handle) }
                val publication = pinnedNative.open(temporary, WindowsInstallNative.DELETE, false)
                var published = false
                return try {
                    val identity = native.deniedInputIdentity(publication)
                    native.publishExportNoReplace(publication, name)
                    published = true
                    identity
                } finally {
                    try { if (!published) native.delete(publication) } finally { pinnedNative.close(publication) }
                }
            }
            val copiedPackage = "$input\\package.msi"
            val output = pinnedNative.open(copiedPackage, WindowsInstallNative.READ_WRITE, false, fileAcl)
            val packageIdentity = try { native.deniedInputIdentity(output) }
                catch (failure: Throwable) { pinnedNative.close(output); throw failure }
            try {
                val digest = MessageDigest.getInstance("SHA-256")
                var length = 0L
                Files.newInputStream(packageFile).use { source ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        require(length + count <= asset.sizeBytes) { "INVALID_ARGUMENT" }
                        var offset = 0
                        while (offset < count) {
                            val remaining = if (offset == 0) buffer else buffer.copyOfRange(offset, count)
                            val written = native.writeExportChunk(output, length + offset, remaining, count - offset)
                            check(written > 0) { "UNAVAILABLE" }
                            offset += written
                        }
                        digest.update(buffer, 0, count)
                        length += count
                    }
                }
                require(length == asset.sizeBytes && digest.digest().joinToString("") { "%02x".format(it) } == asset.sha256) { "INVALID_ARGUMENT" }
                native.syncExport(output)
            } finally { pinnedNative.close(output) }
            val request = DesktopWindowsInstallRequest(jobId, sid, owner.pid(), started, launcher,
                copiedPackage, asset.sha256, asset.sizeBytes, workspaceDirectory.toAbsolutePath().normalize().toString(),
                frontend?.pid, frontend?.startedAtEpochMillis)
            val requestBytes = request.encode()
            val requestIdentity = writeRecord("request.json", requestBytes)
            var reader: DesktopInstallJobStore.Reader? = null
            val receiptPrepared = DesktopWindowsPreparedInstall(jobId,
                readReceipt = {
                    val active = reader ?: DesktopInstallJobStore.production().open(jobId).also { reader = it }
                    active.read()
                },
                publishCommit = { writeRecord("commit.json", "{\"version\":1,\"jobId\":\"$jobId\"}".encodeToByteArray()) },
                requestCancellation = {
                    val active = reader ?: DesktopInstallJobStore.production().open(jobId).also { reader = it }
                    active.requestCancellation()
                },
                release = { try { reader?.close() } finally { closeWindowsDeniedInputHolders(pins).getOrThrow() } },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            val prepared = DesktopWindowsUnstartedCancellation(receiptPrepared,
                canProveNotStarted = {
                    windowsInstallDefinitelyNotStarted(coordinatorAttempted, coordinatorDenied, null)
                },
                recordNotStarted = { correlations.markNotStarted(correlation, jobId,
                    ControlCode.CANCELLED) },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            // Correlation and retained witnesses precede ShellExecute. Only native ERROR_CANCELLED
            // proves this attempt did not create a coordinator; an uncertain reply is never replayed.
            deniedWitness = DesktopWindowsDeniedInputWitness(binding, request, inputRootIdentity, inputIdentity,
                requestIdentity, packageIdentity, DesktopWindowsDeniedInputCleanup.sha(requestBytes))
            check(protectedInspectionHolders.isEmpty() && !deniedInputCleanup.blocksPreparation() && !completedInputCleanup.blocksPreparation()) { "PERSISTENCE_FAILED" }
            pending = prepared
            launched = true
            coordinatorAttempted = true
            try {
                launchWindowsInstallCoordinator(helper, jobId)
            } catch (denied: DesktopWindowsCoordinatorLaunchFailure) {
                if (denied.nativeCode == 1223) {
                    coordinatorDenied = true
                    deniedNativeCode = denied.nativeCode
                }
                throw denied
            }
            // Protected job creation is asynchronous. Missing files are retried only during this bounded readiness phase.
            val authorizationDeadline = System.nanoTime() + 180_000_000_000L
            while (reader == null) {
                try { reader = DesktopInstallJobStore.production().open(jobId) }
                catch (missing: WindowsInstallNativeFailure) {
                    if (missing.code != 2 && missing.code != 3) throw missing
                    check(System.nanoTime() < authorizationDeadline) { "OUTCOME_UNKNOWN" }
                    delay(50)
                }
            }
            receiptPrepared.awaitAuthorization().getOrThrow()
            Result.success(prepared)
        } catch (failure: Exception) {
            var reportedFailure: Throwable = failure
            // Admission can fail before returning a lease. Its cleanup carrier still owns
            // native capabilities and must join the same no-worker retry owner.
            if (!coordinatorAttempted && failure is DesktopWindowsAdmissionCleanupFailure) {
                pins += failure.retained
            }
            if (windowsInstallDefinitelyNotStarted(coordinatorAttempted, coordinatorDenied, null)) {
                launched = false
                val retired = recordedJobId?.let { job -> runCatching {
                    correlations.markNotStarted(correlation, job,
                        ControlCode.CANCELLED)
                } }
                if (retired == null || retired.isSuccess) {
                    pending = null
                    runCatching { onCancellationConfirmed() }
                } else {
                    reportedFailure = IllegalStateException("OUTCOME_UNKNOWN", retired.exceptionOrNull())
                }
            }
            if (!launched) {
                val witness = deniedWitness
                val code = deniedNativeCode
                if (witness != null && code == 1223) {
                    // Own every original holder, including failed closes, until exact cleanup settles.
                    deniedInputCleanup.retainNativeDenial(witness, requireNotNull(code), pins)
                    // The terminal cancellation outcome remains authoritative; owner maintenance
                    // reports a retained resource/cleanup failure separately.
                } else deniedInputCleanup.retainUncertainHolders(pins).onFailure { closeFailure ->
                    val preparationFailure = reportedFailure
                    reportedFailure = IllegalStateException("PERSISTENCE_FAILED", preparationFailure).also {
                        it.addSuppressed(closeFailure)
                    }
                }
            }
            // Keep handles and job identity until explicit cancellation/reconciliation after worker creation.
            val active = pending
            if (active != null) Result.failure(DesktopInstallPreparationFailure(active, reportedFailure)) else Result.failure(reportedFailure)
        }
    }

    private fun localAppData(): String {
        val pointer = PointerByReference()
        val result = Shell32.INSTANCE.SHGetKnownFolderPath(KnownFolders.FOLDERID_LocalAppData, 0, null, pointer)
        check(result.toInt() == 0) { "UNAVAILABLE" }
        return try { requireNotNull(pointer.value).getWideString(0) } finally { Ole32.INSTANCE.CoTaskMemFree(pointer.value) }
    }


}

/** Null worker means ProcessBuilder never returned a process; attempted unknown coordinators remain blocking. */
internal fun windowsInstallDefinitelyNotStarted(coordinatorAttempted: Boolean, coordinatorDenied: Boolean, workerAlive: Boolean?): Boolean =
    (!coordinatorAttempted || coordinatorDenied) && workerAlive != true

/** Late worker exit can complete an earlier denied launch; no protected receipt is fabricated. */
internal class DesktopWindowsUnstartedCancellation(
    private val delegate: DesktopPreparedInstall,
    private val canProveNotStarted: () -> Boolean,
    private val recordNotStarted: () -> Unit,
    private val onCancellationConfirmed: () -> Unit,
) : DesktopPreparedInstall {
    override val jobId get() = delegate.jobId
    private var cancelled = false
    private var closed = false
    override suspend fun commit(): Result<Unit> =
        if (closed || cancelled) Result.failure(IllegalStateException("CANCELLED")) else delegate.commit()
    override fun cancel(): Result<Unit> = runCatching {
        check(!closed)
        if (cancelled) return@runCatching
        if (canProveNotStarted()) {
            recordNotStarted()
            cancelled = true
            onCancellationConfirmed()
        } else {
            delegate.cancel().getOrThrow()
            cancelled = true
        }
    }
    override fun close() { if (!closed) { closed = true; delegate.close() } }
}

/** Standard Windows argv quoting, including backslashes before a quote and at the closing quote. */
internal fun windowsInstallArgument(value: String): String = buildString {
    append('"')
    var slashes = 0
    for (character in value) {
        if (character == '\\') { slashes++; continue }
        repeat(if (character == '"') slashes * 2 + 1 else slashes) { append('\\') }
        slashes = 0
        append(character)
    }
    repeat(slashes * 2) { append('\\') }
    append('"')
}

/** The two public Windows images share one installation; every other executable remains invalid. */
internal fun desktopWindowsUpdateLauncher(command: String,
    exists: (String) -> Boolean = { Files.isRegularFile(Path.of(it), java.nio.file.LinkOption.NOFOLLOW_LINKS) },
): String? = runCatching {
    val canonical = DesktopWindowsInstallJobBackend.canonical(command)
    val leaf = canonical.substringAfterLast('\\').lowercase(java.util.Locale.ROOT)
    require(leaf in setOf("vpn-control.exe", "vpn-control-cli.exe"))
    val launcher = canonical.substringBeforeLast('\\') + "\\vpn-control.exe"
    launcher.takeIf(exists)
}.getOrNull()

/** Retain the native process handle through image verification; never terminate an uncertain launch. */
internal fun launchWindowsInstallCoordinator(
    helper: DesktopWindowsInstallHelperLease,
    jobId: String,
    launch: (String, String) -> WinNT.HANDLE = ::shellExecuteWindowsInstallCoordinator,
    closeProcess: (WinNT.HANDLE) -> Unit = { Kernel32.INSTANCE.CloseHandle(it); Unit },
) {
    val process = launch(helper.executable, helper.parameters(jobId))
    try { helper.verifyStartedProcess(process) }
    finally { closeProcess(process) }
}

private fun shellExecuteWindowsInstallCoordinator(executable: String, parameters: String): WinNT.HANDLE {
    val info = ShellAPI.SHELLEXECUTEINFO()
    info.fMask = 0x00000040 // SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = parameters
    info.nShow = 0
    check(parameters.length + executable.length < 32760) { "INVALID_ARGUMENT" }
    if (!Shell32.INSTANCE.ShellExecuteEx(info)) {
        val code = Kernel32.INSTANCE.GetLastError()
        throw DesktopWindowsCoordinatorLaunchFailure(code)
    }
    return info.hProcess ?: error("OUTCOME_UNKNOWN")
}

/** Narrow existing-object primitives; no method grants an installation or a cleanup verdict. */
internal interface WindowsDeniedInputNative : WindowsInstallNative {
    fun openDeniedInput(path: String): WindowsInstallNative.Handle
    fun deniedInputIdentity(handle: WindowsInstallNative.Handle): String
    fun deniedInputCanonicalPath(handle: WindowsInstallNative.Handle): String
    fun deniedInputPersistentAcl(handle: WindowsInstallNative.Handle): Boolean
    fun readDeniedInputChunk(handle: WindowsInstallNative.Handle, offset: Long, bytes: ByteArray, count: Int): Int
    /** At most three names: the two expected leaves plus one rejecting overflow witness. */
    fun deniedInputChildren(path: String): List<String>
}

/** Produced only by the native ShellExecute failure branch, preserving the actual Win32 code. */
internal class DesktopWindowsCoordinatorLaunchFailure(val nativeCode: Int) :
    IllegalStateException(if (nativeCode == 1223) "CANCELLED" else "UNAVAILABLE")

/** Original pinned object identities, never reconstructed from a cold request or a path alone. */
internal data class DesktopWindowsDeniedInputWitness(
    val binding: DesktopInstallCorrelationRecord,
    val request: DesktopWindowsInstallRequest,
    val rootIdentity: String,
    val directoryIdentity: String,
    val requestIdentity: String,
    val packageIdentity: String,
    val requestSha256: String,
) {
    init {
        require(binding.receiptAuthority == DesktopInstallReceiptAuthority.MACHINE && binding.jobId == request.jobId)
        require(listOf(rootIdentity, directoryIdentity, requestIdentity, packageIdentity).all { it.matches(Regex("[a-f0-9]{48}")) })
        require(requestSha256.matches(Regex("[a-f0-9]{64}")))
    }
    override fun toString() = "DesktopWindowsDeniedInputWitness(jobId=${binding.jobId}, metadata=<private>)"
}

/** Attempt all holders; failed close capabilities stay owned and never become claimed releases. */
internal fun closeWindowsDeniedInputHolders(holders: MutableList<AutoCloseable>): Result<Unit> = runCatching {
    var failure: Throwable? = null
    for (index in holders.indices.reversed()) {
        try { holders[index].close(); holders.removeAt(index) }
        catch (error: Throwable) { failure = failure ?: error }
    }
    failure?.let { throw IllegalStateException("PERSISTENCE_FAILED", it) }
}

/** Own every native handle before returning it, including transfer-pin construction and transient writes.
 * Successful closes are idempotent through this facade: an enclosing pin group can retry after
 * partially closing without retrying an already closed native handle. Failed capabilities remain owned.
 */
internal class DesktopWindowsDeniedInputHandles(private val source: WindowsDeniedInputNative) : AutoCloseable {
    private val holders = java.util.IdentityHashMap<WindowsInstallNative.Handle, AutoCloseable>()
    val native: WindowsDeniedInputNative = object : WindowsDeniedInputNative by source {
        override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?) =
            retain(source.open(path, access, shareDelete, createSddl))
        override fun openDeniedInput(path: String) = retain(source.openDeniedInput(path))
        override fun close(handle: WindowsInstallNative.Handle) { holders[handle]?.close() }
    }
    private fun retain(handle: WindowsInstallNative.Handle): WindowsInstallNative.Handle {
        check(!holders.containsKey(handle))
        holders[handle] = AutoCloseable { source.close(handle); holders.remove(handle) }
        return handle
    }
    override fun close() {
        // Attempt every outstanding capability even if an enclosing group stopped at its first error.
        closeWindowsDeniedInputHolders(holders.values.toMutableList()).getOrThrow()
    }
}

/** Ordinary owner maintenance for one proven native1223 attempt; no helper or coordinator launch. */
internal class DesktopWindowsDeniedInputCleanup(
    private val inputRoot: String,
    private val workspaceDirectory: String,
    private val native: WindowsDeniedInputNative,
    private val ancestry: WindowsAdmissionNative,
    private val read: (DesktopInstallCorrelationRecord) -> DesktopInstallCorrelationRecovery,
    private val requireProtectedAbsent: (DesktopInstallCorrelationRecord) -> Unit,
    private val hasPending: () -> Boolean = { false },
) {
    private class Retained(val witness: DesktopWindowsDeniedInputWitness, val holders: MutableList<AutoCloseable>) {
        val deletionAttempted = mutableSetOf<String>()
    }
    private val retained = mutableMapOf<DesktopInstallCorrelationRecord, Retained>()
    private val unreleasedHolders = mutableListOf<AutoCloseable>()
    private val root = DesktopWindowsInstallJobBackend.canonical(inputRoot)

    @Synchronized fun retainNativeDenial(witness: DesktopWindowsDeniedInputWitness, nativeCode: Int,
        prepareHolders: MutableList<AutoCloseable>): Result<Unit> = runCatching {
        require(nativeCode == 1223) { "OUTCOME_UNKNOWN" }
        require(retained.size < 256 && witness.binding !in retained) { "BUSY" }
        retained[witness.binding] = Retained(witness, prepareHolders)
        closeWindowsDeniedInputHolders(prepareHolders).getOrThrow()
    }

    @Synchronized fun blocksPreparation(): Boolean = unreleasedHolders.isNotEmpty() || retained.values.any { it.holders.isNotEmpty() }

    /** Independent of record cleanupCode: probes and arbitrary prelaunch failures also own debt. */
    @Synchronized fun reconcileHolders(): Result<Unit> = runCatching {
        val groups = listOf(unreleasedHolders) + retained.values.map { it.holders }
        var failure: Throwable? = null
        for (group in groups) closeWindowsDeniedInputHolders(group).onFailure { failure = failure ?: it }
        failure?.let { throw IllegalStateException("PERSISTENCE_FAILED", it) }
    }

    @Synchronized fun retainUncertainHolders(prepareHolders: MutableList<AutoCloseable>): Result<Unit> {
        unreleasedHolders.addAll(prepareHolders)
        prepareHolders.clear()
        return reconcileHolders()
    }

    @Synchronized fun release(record: DesktopInstallCorrelationRecovery): Result<Unit> = runCatching {
        val binding = requireNotNull(record.binding)
        require(!hasPending()) { "BUSY" }
        require(record.notStarted && record.receipt == null && record.code == ControlCode.CANCELLED &&
            binding.receiptAuthority == DesktopInstallReceiptAuthority.MACHINE) { "OUTCOME_UNKNOWN" }
        fun revalidate() {
            require(read(binding).copy(cleanupCode = null) == record.copy(cleanupCode = null)) { "CONFLICT" }
            requireProtectedAbsent(binding)
        }
        revalidate()
        closeWindowsDeniedInputHolders(unreleasedHolders).getOrThrow()
        val proof = retained[binding]
        proof?.let { closeWindowsDeniedInputHolders(it.holders).getOrThrow() }
        withRoot { rootHandle, holders, api ->
            if (rootHandle == null) return@withRoot
            val job = openMissing(root + "\\" + binding.jobId, delete = true, api = api) ?: return@withRoot
            val jobHolder = AutoCloseable { api.close(job) }
            holders += jobHolder
            requireNotNull(proof) { "PERSISTENCE_FAILED" } // Cold present inputs retain missing authority.
            val witness = proof.witness
            require(witness.request.principalSid == ancestry.currentSid()) { "PERMISSION_DENIED" }
            verify(rootHandle, directory = true)
            require(native.deniedInputIdentity(rootHandle) == witness.rootIdentity) { "CONFLICT" }
            verify(job, directory = true)
            require(native.deniedInputIdentity(job) == witness.directoryIdentity) { "CONFLICT" }
            linked(rootHandle, job)
            val path = root + "\\" + binding.jobId
            val children = native.deniedInputChildren(path)
            require(children.size <= 2 && children.all { it in setOf("request.json", "package.msi") } &&
                children.distinct().size == children.size) { "CONFLICT" }
            val opened = mutableMapOf<String, Pair<WindowsInstallNative.Handle, AutoCloseable>>()
            for ((name, identity) in listOf("request.json" to witness.requestIdentity, "package.msi" to witness.packageIdentity)) {
                val handle = openMissing(path + "\\" + name, delete = true, api = api)
                if (handle == null) {
                    require(name in proof.deletionAttempted) { "CONFLICT" }
                    continue
                }
                val holder = AutoCloseable { api.close(handle) }
                holders += holder
                opened[name] = handle to holder
                verify(handle, directory = false)
                linked(job, handle)
                require(native.deniedInputIdentity(handle) == identity) { "CONFLICT" }
            }
            opened["request.json"]?.first?.let { handle ->
                val bytes = native.read(handle, DesktopWindowsInstallRequest.MAX_BYTES + 1)
                require(bytes.size <= DesktopWindowsInstallRequest.MAX_BYTES && native.inspect(handle).size == bytes.size.toLong()) { "CONFLICT" }
                require(sha(bytes) == witness.requestSha256 && DesktopWindowsInstallRequest.decode(bytes) == witness.request) { "CONFLICT" }
            }
            require(witness.request.stateDirectory.equals(workspaceDirectory, ignoreCase = true) &&
                witness.request.jobId == binding.jobId &&
                witness.request.packageFile.equals(path + "\\package.msi", ignoreCase = true)) { "CONFLICT" }
            opened["package.msi"]?.first?.let { handle ->
                require(native.inspect(handle).size == witness.request.packageSize) { "CONFLICT" }
                val digest = MessageDigest.getInstance("SHA-256")
                val bytes = ByteArray(8192)
                var length = 0L
                while (true) {
                    val count = native.readDeniedInputChunk(handle, length, bytes, bytes.size)
                    require(count in 0..bytes.size && count.toLong() <= witness.request.packageSize - length) { "CONFLICT" }
                    if (count == 0) break
                    digest.update(bytes, 0, count); length += count
                }
                require(length == witness.request.packageSize && native.inspect(handle).size == length &&
                    digest.digest().joinToString("") { "%02x".format(it) } == witness.request.packageSha256 &&
                    native.deniedInputIdentity(handle) == witness.packageIdentity) { "CONFLICT" }
            }
            revalidate()
            // Never recurse. A new foreign child remains untouched and makes empty-directory deletion fail.
            for (name in listOf("package.msi", "request.json")) {
                opened[name]?.let { (handle, holder) ->
                    proof.deletionAttempted += name
                    native.delete(handle)
                    holder.close(); holders.remove(holder)
                }
            }
            native.delete(job)
            // Directory deletion finishes only after the retained job handle is successfully closed.
            jobHolder.close(); holders.remove(jobHolder)
        }.getOrThrow()
        // Only removal plus all successful closes clears witnesses; history is left intact.
        retained.remove(binding)
        Unit
    }.recoverCatching { throw IllegalStateException("PERSISTENCE_FAILED", it) }

    /** Read-only pruning guard: only precise native whole-input absence permits forgetting a binding. */
    @Synchronized fun inputAbsent(binding: DesktopInstallCorrelationRecord): Boolean = runCatching {
        if (blocksPreparation()) return@runCatching false
        requireProtectedAbsent(binding)
        var absent = false
        withRoot { rootHandle, holders, api ->
            if (rootHandle == null) { absent = true; return@withRoot }
            val handle = openMissing(root + "\\" + binding.jobId, delete = false, api = api)
            if (handle == null) absent = true else {
                holders += AutoCloseable { api.close(handle) }
                verify(handle, directory = true); linked(rootHandle, handle)
            }
        }.getOrThrow()
        val settled = absent && !blocksPreparation()
        if (settled) retained.remove(binding)
        settled
    }.getOrDefault(false)

    private fun openMissing(path: String, delete: Boolean, api: WindowsDeniedInputNative = native): WindowsInstallNative.Handle? = try {
        if (delete) api.openDeniedInput(path) else api.open(path, WindowsInstallNative.INSPECT, false)
    } catch (error: WindowsInstallNativeFailure) {
        // An explicitly opened final child may be absent; an inaccessible ancestor is never absence.
        if (error.code == 2 || error.code == 3) null else throw error
    }

    private fun <T> withRoot(action: (WindowsInstallNative.Handle?, MutableList<AutoCloseable>, WindowsDeniedInputNative) -> T): Result<T> {
        val nativeHandles = DesktopWindowsDeniedInputHandles(native)
        val api = nativeHandles.native
        val holders = mutableListOf<AutoCloseable>(nativeHandles)
        var result = runCatching {
            val sid = ancestry.currentSid()
            val pins = DesktopWindowsTransferPins.open(root.substringBeforeLast('\\'), sid, api, ancestry)
            holders += pins
            val rootHandle = openMissing(root, delete = false, api = api)
            if (rootHandle != null) {
                holders += AutoCloseable { api.close(rootHandle) }
                verify(rootHandle, directory = true)
                // Use the same canonical-path API for both objects.
                linked(pins.parentHandle, rootHandle)
            }
            action(rootHandle, holders, api)
        }
        val close = closeWindowsDeniedInputHolders(holders)
        if (close.isFailure) {
            // A failed native close remains owned. It blocks further preparation and is retried only as cleanup.
            unreleasedHolders.addAll(holders)
            result = Result.failure(close.exceptionOrNull()!!)
        }
        return result
    }

    private fun linked(parent: WindowsInstallNative.Handle, child: WindowsInstallNative.Handle) {
        require(native.deniedInputCanonicalPath(child).substringBeforeLast('\\') ==
            native.deniedInputCanonicalPath(parent).trimEnd('\\')) { "CONFLICT" }
    }

    private fun verify(handle: WindowsInstallNative.Handle, directory: Boolean) {
        require(native.deniedInputPersistentAcl(handle)) { "PERMISSION_DENIED" }
        val info = native.inspect(handle)
        val sid = ancestry.currentSid()
        require(info.disk && info.directory == directory && info.attributes and 0x400 == 0 && info.reparseTag == 0 &&
            info.owner == sid && (directory || info.links == 1)) { "PERMISSION_DENIED" }
        val acl = requireNotNull(info.dacl)
        require(acl.isNotEmpty()) { "PERMISSION_DENIED" }
        for (ace in acl) {
            require(ace.type in 0..1 && ace.flags and 0x1f.inv() == 0) { "PERMISSION_DENIED" }
            if (ace.type == 1 || ace.sid == sid) continue
            require(ace.sid in setOf("S-1-5-32-544", "S-1-5-18") && ace.mask and 0xA01200A9.toInt().inv() == 0) {
                "PERMISSION_DENIED"
            }
        }
    }

    companion object {
        fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
