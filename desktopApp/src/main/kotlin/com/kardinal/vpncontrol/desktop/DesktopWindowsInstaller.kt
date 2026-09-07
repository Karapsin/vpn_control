package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Creates private immutable input and launches only the bundled captured workers through trusted OS images. */
internal class DesktopWindowsInstaller(private val workspaceDirectory: Path = DesktopWorkspacePaths.root()) {
    // Once a worker exists, even a lost authorization result must not admit an unrelated installation.
    private var pending: DesktopPreparedInstall? = null
    private val correlations = DesktopInstallCorrelationJournal(workspaceDirectory)

    fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> = runCatching { correlations.recoverAll() }

    /** Release only after re-reading the exact protected terminal record; never publish cancellation. */
    fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> = runCatching {
        require(receipt.phase.terminal)
        val recovered = correlations.recoverAll().single { it.binding?.correlation == correlation }
        require(recovered.binding?.jobId == receipt.jobId && recovered.receipt == receipt)
        pending?.let { require(it.jobId == receipt.jobId); it.close() }
        pending = null
    }

    suspend fun prepare(packageFile: Path, asset: UpdateAsset, launcher: String,
        correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity? = null,
        onCancellationConfirmed: () -> Unit = {},
    ): Result<DesktopPreparedInstall> = withContext(Dispatchers.IO) {
        if (pending != null) return@withContext Result.failure(IllegalStateException("BUSY"))
        val native = JnaWindowsInstallNative()
        val pins = mutableListOf<AutoCloseable>()
        var launched = false
        var originalWorker: Process? = null
        var coordinatorAttempted = false
        var coordinatorDenied = false
        var workerExitedBeforeReady = false
        var recordedJobId: String? = null
        try {
            correlations.requireNew(correlation)
            val sid = JnaWindowsInstallAdmission().currentSid()
            val owner = ProcessHandle.current()
            val started = requireNotNull(owner.info().startInstant().orElse(null)).toEpochMilli()
            val jobId = UUID.randomUUID().toString()
            val local = localAppData()
            pins += DesktopWindowsTransferPins.open(local, sid, native)
            val inputRoot = "$local\\vpn-control-install-inputs"
            val directoryAcl = "O:${sid}G:${sid}D:P(A;OICI;FA;;;$sid)(A;OICI;GRGX;;;BA)(A;OICI;GRGX;;;SY)"
            native.createDirectory(inputRoot, directoryAcl, true)
            pins += DesktopWindowsTransferPins.open(inputRoot, sid, native)
            val input = "$inputRoot\\$jobId"
            native.createDirectory(input, directoryAcl, false)
            pins += DesktopWindowsTransferPins.open(input, sid, native)
            val fileAcl = "O:${sid}G:${sid}D:P(A;;FA;;;$sid)(A;;GR;;;BA)(A;;GR;;;SY)"
            fun writeRecord(name: String, bytes: ByteArray) {
                val temporary = "$input\\record-${UUID.randomUUID()}.tmp"
                val handle = native.open(temporary, WindowsInstallNative.READ_WRITE, false, fileAcl)
                try { native.writeAndSync(handle, bytes) } finally { native.close(handle) }
                val publication = native.open(temporary, WindowsInstallNative.DELETE, false)
                var published = false
                try {
                    native.publishExportNoReplace(publication, name)
                    published = true
                } finally {
                    try { if (!published) native.delete(publication) } finally { native.close(publication) }
                }
            }
            val copiedPackage = "$input\\package.msi"
            val output = native.open(copiedPackage, WindowsInstallNative.READ_WRITE, false, fileAcl)
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
            } finally { native.close(output) }
            val request = DesktopWindowsInstallRequest(jobId, sid, owner.pid(), started, launcher,
                copiedPackage, asset.sha256, asset.sizeBytes, workspaceDirectory.toAbsolutePath().normalize().toString(),
                frontend?.pid, frontend?.startedAtEpochMillis)
            writeRecord("request.json", request.encode())
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
                release = { try { reader?.close() } finally { pins.asReversed().forEach { it.close() }; pins.clear() } },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            val prepared = DesktopWindowsUnstartedCancellation(receiptPrepared,
                canProveNotStarted = {
                    if (!coordinatorAttempted || coordinatorDenied) {
                        // This exact owned worker cannot run MSI without a coordinator's
                        // INSTALLING receipt. Stop it, then require observed exit.
                        originalWorker?.takeIf { it.isAlive }?.let { worker ->
                            worker.destroy()
                            worker.waitFor(5, TimeUnit.SECONDS)
                        }
                    }
                    windowsInstallDefinitelyNotStarted(coordinatorAttempted, coordinatorDenied, originalWorker?.isAlive)
                },
                recordNotStarted = { correlations.markNotStarted(correlation, jobId,
                    if (workerExitedBeforeReady) ControlCode.RUNTIME_FAILED else ControlCode.CANCELLED) },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            val powershell = trustedPowerShell()
            // Persist exact owner-operation/job correlation before any worker can exist.
            // Recovery reads the protected receipt; it never replays this launch.
            correlations.record(correlation, jobId)
            recordedJobId = jobId
            val worker = ProcessBuilder(listOf(powershell) + DesktopWindowsCapturedInstallWorker.arguments(
                DesktopWindowsCapturedInstallWorker.Role.ORIGINAL_USER, jobId, owner.pid()))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            originalWorker = worker
            launched = true
            pending = prepared
            worker.outputStream.close()
            // This record is input, not authorization. The elevated coordinator independently pins its process/token.
            val deadline = System.nanoTime() + 30_000_000_000L
            val ready = "$input\\worker-ready.json"
            while (!Files.exists(Path.of(ready))) {
                if (!worker.isAlive) {
                    workerExitedBeforeReady = true
                    error(ControlCode.RUNTIME_FAILED.name)
                }
                check(System.nanoTime() < deadline) { "OUTCOME_UNKNOWN" }
                delay(50)
            }
            val recordHandle = native.open(ready, WindowsInstallNative.PINNED_READ, false)
            try {
                val record = ControlProtocolCodec.decodeValues(native.read(recordHandle, 4097).also { require(it.size <= 4096) }.decodeToString())
                require(record.keys == setOf("version", "jobId", "pid", "startedAtEpochMillis"))
                require(record["version"] == ControlValue.IntegerValue(1) && record["jobId"] == ControlValue.Text(jobId))
                require(record["pid"] == ControlValue.IntegerValue(worker.pid()))
                require(record["startedAtEpochMillis"] == ControlValue.IntegerValue(
                    requireNotNull(worker.info().startInstant().orElse(null)).toEpochMilli()))
            } finally { native.close(recordHandle) }
            coordinatorAttempted = true
            try {
                launchCoordinator(powershell, DesktopWindowsCapturedInstallWorker.arguments(
                    DesktopWindowsCapturedInstallWorker.Role.COORDINATOR, jobId, owner.pid()))
            } catch (denied: IllegalStateException) {
                if (denied.message == "CANCELLED") {
                    coordinatorDenied = true // ShellExecuteEx returned native ERROR_CANCELLED.
                    // Native ERROR_CANCELLED proves no coordinator was launched. This exact worker
                    // cannot start MSI without an administrator-owned INSTALLING receipt.
                    worker.destroy()
                    worker.waitFor(5, TimeUnit.SECONDS)
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
            var reportedFailure = failure
            if (windowsInstallDefinitelyNotStarted(coordinatorAttempted, coordinatorDenied, originalWorker?.isAlive)) {
                launched = false
                val retired = recordedJobId?.let { job -> runCatching {
                    correlations.markNotStarted(correlation, job,
                        if (workerExitedBeforeReady) ControlCode.RUNTIME_FAILED else ControlCode.CANCELLED)
                } }
                if (retired == null || retired.isSuccess) {
                    pending = null
                    runCatching { onCancellationConfirmed() }
                } else {
                    reportedFailure = IllegalStateException("OUTCOME_UNKNOWN", retired.exceptionOrNull())
                }
            }
            if (!launched) { pins.asReversed().forEach { runCatching { it.close() } }; pins.clear() }
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

    private fun trustedPowerShell(): String {
        val api = Native.load("kernel32", SystemDirectoryApi::class.java)
        return Memory(32768L * 2).use { buffer ->
            val length = api.GetSystemDirectoryW(buffer, 32768)
            require(length in 1 until 32768)
            String(CharArray(length) { buffer.getShort(it.toLong() * 2).toInt().toChar() }) +
                "\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
    }

    private interface SystemDirectoryApi : StdCallLibrary {
        fun GetSystemDirectoryW(output: Pointer, capacity: Int): Int
    }

    private fun launchCoordinator(executable: String, arguments: List<String>) {
        val info = ShellAPI.SHELLEXECUTEINFO()
        info.fMask = 0x00000040 // SEE_MASK_NOCLOSEPROCESS
        info.lpVerb = "runas"
        info.lpFile = executable
        info.lpParameters = arguments.joinToString(" ", transform = ::windowsInstallArgument)
        info.nShow = 0
        check(info.lpParameters.length + executable.length < 32760) { "INVALID_ARGUMENT" }
        if (!Shell32.INSTANCE.ShellExecuteEx(info)) {
            val error = Kernel32.INSTANCE.GetLastError()
            error(if (error == 1223) "CANCELLED" else "UNAVAILABLE")
        }
        info.hProcess?.let { Kernel32.INSTANCE.CloseHandle(it) }
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
