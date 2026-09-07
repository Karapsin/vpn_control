package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

internal interface DesktopMacInstallAdapter {
    suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity? = null, onCancellationConfirmed: () -> Unit = {}): Result<DesktopPreparedInstall>
    fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>>
    fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit>
}

/** Native per-job worker, never the legacy mutable shell helper. Public dispatch waits for native validation. */
internal class DesktopMacInstaller(private val stateDirectory: Path,
    private val isMac: () -> Boolean = { System.getProperty("os.name").startsWith("Mac", true) },
) : DesktopMacInstallAdapter {
    private val correlations = DesktopInstallCorrelationJournal(stateDirectory, readBoundReceipt = { binding ->
        authority(binding.receiptAuthority).store().open(binding.jobId).use { it.read() }
    })
    private var pending: DesktopPreparedInstall? = null

    override fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> = runCatching { correlations.recoverAll() }
    override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> = runCatching {
        require(receipt.phase.terminal)
        val recovered = correlations.recoverAll().single { it.binding?.correlation == correlation }
        require(recovered.binding?.jobId == receipt.jobId && recovered.receipt == receipt)
        pending?.let { require(it.jobId == receipt.jobId); it.close() }
        pending = null
        val input = JnaMacInstallAdmission().homeDirectory().resolve("Library/Application Support/vpn-control-install-inputs").resolve(receipt.jobId)
        val worker = input.resolve("vpn-control-install-worker")
        if (Files.exists(worker, NOFOLLOW_LINKS)) {
            // Cleanup has its own descriptor-bound terminal receipt check and never runs elevated.
            val cleanup = ProcessBuilder(DesktopMacWorkerLaunch.cleanup(worker, receipt.jobId, ProcessHandle.current().pid()))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            cleanup.outputStream.close()
            check(cleanup.waitFor(30, TimeUnit.SECONDS) && cleanup.exitValue() == 0) { "PERSISTENCE_FAILED" }
        }
    }

    override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> = withContext(Dispatchers.IO) {
        if (!isMac() || asset.platform != UpdatePlatform.MACOS || asset.packageType != UpdatePackageType.DMG)
            return@withContext Result.failure(IllegalStateException("UNSUPPORTED"))
        if (pending != null) return@withContext Result.failure(IllegalStateException("BUSY"))
        var watcher: Process? = null
        var coordinator: Process? = null
        var coordinatorAttempted = false
        var authorizationReplyRead = false
        var authorizationRejected: ControlCode? = null
        var reader: DesktopInstallJobStore.Reader? = null
        try {
            correlations.requireNew(correlation)
            val native = JnaMacInstallAdmission()
            val owner = DesktopMacInstallProcesses.read(ProcessHandle.current().pid())
            require(owner.uid == native.currentUid())
            val launcher = Path.of(owner.executable)
            // Reinspect the actual owner image/ancestry before creating any job. This lease is
            // additional to process admission; the worker retains its own descriptors afterward.
            DesktopMacInstallAdmission.enter(launcher, native, roots = emptyList()).close()
            val bundle = launcher.parent.parent.parent
            val bundleOwner = (Files.getAttribute(bundle, "unix:uid", NOFOLLOW_LINKS) as Number).toLong()
            val kind = if (bundleOwner == owner.uid && Files.isWritable(bundle) && Files.isWritable(bundle.parent))
                DesktopMacInstallAuthority.USER_LOCAL else DesktopMacInstallAuthority.MACHINE
            val policy = DesktopMacReceiptAuthority.production(kind, native)
            val job = UUID.randomUUID().toString()
            val input = native.homeDirectory().resolve("Library/Application Support/vpn-control-install-inputs").resolve(job)
            Files.createDirectories(input, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            require(Files.getPosixFilePermissions(input) == PosixFilePermissions.fromString("rwx------"))
            val worker = input.resolve("vpn-control-install-worker")
            val architecture = when (System.getProperty("os.arch").lowercase()) {
                "aarch64", "arm64" -> "arm64"
                "amd64", "x86_64" -> "amd64"
                else -> error("UNSUPPORTED")
            }
            val workerBytes = requireNotNull(javaClass.getResourceAsStream("/bin/darwin-$architecture/vpn-control-install-worker")) {
                "Packaged installer worker unavailable"
            }.use { it.readNBytes(1024*1024+1) }
            require(workerBytes.size in 1..1024*1024)
            DesktopPrivateExportWriter.write(worker.toString(), workerBytes).getOrThrow()
            Files.setPosixFilePermissions(worker, PosixFilePermissions.fromString("rwx------"))
            val copied = input.resolve("package.dmg")
            var count = 0L
            val digest = MessageDigest.getInstance("SHA-256")
            DesktopPrivateExportWriter.writeChunks(copied.toString()) { emit ->
                Files.newInputStream(packageFile, NOFOLLOW_LINKS).use { source ->
                    val bytes = ByteArray(8192)
                    while (true) {
                        val read = source.read(bytes)
                        if (read < 0) break
                        check(read > 0 && count <= asset.sizeBytes - read) { "INVALID_ARGUMENT" }
                        emit(bytes, read); digest.update(bytes, 0, read); count += read
                    }
                }
                check(count == asset.sizeBytes && digest.digest().joinToString("") { "%02x".format(it) } == asset.sha256) { "INVALID_ARGUMENT" }
            }.getOrThrow()
            val attached = frontend?.let {
                require(it.isStillSameProcess()) { "CONFLICT" }
                DesktopMacInstallProcesses.read(it.pid)
            }
            val request = DesktopMacInstallRequest(job, kind, owner, attached, copied.toString(), count, asset.sha256,
                stateDirectory.toAbsolutePath().normalize().toString())
            macInstallPublishRecord(input.resolve("request"), request.encode())
            fun receiptReader() = reader ?: policy.store().open(job).also { reader = it }
            val receiptPrepared = DesktopReceiptPreparedInstall(job,
                readReceipt = { receiptReader().read() },
                publishCommit = { macInstallPublishRecord(input.resolve("commit"), "$job\n".encodeToByteArray()) },
                requestCancellation = { receiptReader().requestCancellation() },
                release = { reader?.close() },
                timeoutMillis = 180_000,
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
                authorizationFailure = {
                    val process = coordinator
                    if (kind == DesktopMacInstallAuthority.MACHINE && process != null &&
                        !process.isAlive && !authorizationReplyRead) {
                        authorizationReplyRead = true
                        authorizationRejected = DesktopMacAuthorizationReply.notStartedCode(job,
                            process.exitValue(), process.inputStream.use { it.readNBytes(257) })
                    }
                    authorizationRejected?.let { IllegalStateException(it.name) }
                })
            val prepared = DesktopMacUnstartedCancellation(receiptPrepared,
                canProveNotStarted = {
                    if (!coordinatorAttempted) watcher?.takeIf { it.isAlive }?.let {
                        // This exact original-user watcher cannot replace an app by itself.
                        it.destroy(); it.waitFor(5, TimeUnit.SECONDS)
                    }
                    !coordinatorAttempted && watcher?.isAlive != true
                }, recordNotStarted = { correlations.markNotStarted(correlation, job) },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() })
            correlations.record(correlation, job, if (kind == DesktopMacInstallAuthority.USER_LOCAL)
                DesktopInstallReceiptAuthority.MACOS_USER_LOCAL else DesktopInstallReceiptAuthority.MACHINE)
            pending = prepared
            watcher = ProcessBuilder(DesktopMacWorkerLaunch.watcher(worker, job, owner.pid))
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            watcher.outputStream.use { it.write(request.encode()) }
            val deadline = System.nanoTime()+30_000_000_000L
            val ready = ByteArrayOutputStream()
            while (ready.toByteArray().count { it == 10.toByte() } < 4) {
                check(watcher.isAlive && System.nanoTime() < deadline) { "OUTCOME_UNKNOWN" }
                val available = watcher.inputStream.available()
                if (available > 0) {
                    ready.write(watcher.inputStream.readNBytes(minOf(available, 257-ready.size())))
                    check(ready.size() <= 256) { "INVALID_ARGUMENT" }
                }
                delay(50)
            }
            val captured = DesktopMacInstallProcesses.read(watcher.pid())
            check(captured.uid == owner.uid && captured.executable == worker.toString()) { "CONFLICT" }
            val expected = "$job\n${captured.pid}\n${captured.startSeconds}\n${captured.startMicroseconds}\n".encodeToByteArray()
            check(ready.toByteArray().contentEquals(expected)) { "CONFLICT" }
            macInstallPublishRecord(input.resolve("watcher"), expected)
            coordinatorAttempted = true
            coordinator = ProcessBuilder(DesktopMacWorkerLaunch.coordinator(worker, kind, job, owner.pid))
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            coordinator.outputStream.close()
            receiptPrepared.awaitAuthorization().getOrThrow()
            check(watcher.isAlive) { "CONFLICT" }
            Result.success(prepared)
        } catch (cancelled: CancellationException) {
            pending?.let { active ->
                val result = withContext(NonCancellable) { active.cancel() }
                if (result.isSuccess) active.close()
                else throw DesktopInstallPreparationFailure(active, IllegalStateException("OUTCOME_UNKNOWN", cancelled))
            }
            throw cancelled
        } catch (failure: Exception) {
            var reported = failure
            authorizationRejected?.let { code ->
                // Only the exact completed authorization child can establish this boundary.
                // The original-user watcher cannot install on its own. Confirm its exit,
                // then let the journal independently reject any existing/inaccessible receipt.
                runCatching {
                    watcher?.takeIf { it.isAlive }?.let { it.destroy(); it.waitFor(5, TimeUnit.SECONDS) }
                    check(watcher?.isAlive != true) { "OUTCOME_UNKNOWN" }
                    val active = requireNotNull(pending)
                    correlations.markNotStarted(correlation, active.jobId, code)
                    active.close()
                    pending = null
                    reported = IllegalStateException(code.name)
                }.onFailure { reported = IllegalStateException("OUTCOME_UNKNOWN", it) }
            }
            if (!coordinatorAttempted) pending?.let { active ->
                val result = active.cancel()
                if (result.isSuccess) active.close() else reported = IllegalStateException("OUTCOME_UNKNOWN", result.exceptionOrNull())
            }
            // An osascript exit alone does not prove no privileged worker started. Preserve
            // exact correlation and protected polling; never retry installation from the journal.
            pending?.let { Result.failure(DesktopInstallPreparationFailure(it, reported)) } ?: Result.failure(reported)
        }
    }

    private fun authority(value: DesktopInstallReceiptAuthority) = DesktopMacReceiptAuthority.production(when (value) {
        DesktopInstallReceiptAuthority.MACHINE -> DesktopMacInstallAuthority.MACHINE
        DesktopInstallReceiptAuthority.MACOS_USER_LOCAL -> DesktopMacInstallAuthority.USER_LOCAL
    })
}

internal fun macInstallPublishRecord(target: Path, bytes: ByteArray) {
    require(target.fileName.toString() in setOf("request", "watcher", "commit") && bytes.size in 1..16384)
    DesktopPrivateExportWriter.write(target.toString(), bytes).getOrThrow()
}

internal class DesktopMacUnstartedCancellation(private val delegate: DesktopPreparedInstall,
    private val canProveNotStarted: () -> Boolean, private val recordNotStarted: () -> Unit,
    private val onCancellationConfirmed: () -> Unit) : DesktopPreparedInstall {
    override val jobId get() = delegate.jobId
    private var cancelled = false
    private var closed = false
    override suspend fun commit(): Result<Unit> = if (closed || cancelled) Result.failure(IllegalStateException("CANCELLED")) else delegate.commit()
    override fun cancel(): Result<Unit> = runCatching {
        check(!closed)
        if (cancelled) return@runCatching
        if (canProveNotStarted()) { recordNotStarted(); cancelled = true; onCancellationConfirmed() }
        else { delegate.cancel().getOrThrow(); cancelled = true }
    }
    override fun close() { if (!closed) { closed = true; delegate.close() } }
}
