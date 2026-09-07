package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.ReadableByteChannel
import java.io.OutputStream
import java.io.ByteArrayOutputStream
import java.nio.file.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors

internal interface DesktopLinuxInstallAdapter {
    suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity? = null,
        onCancellationConfirmed: () -> Unit = {}): Result<DesktopPreparedInstall>
    fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>>
    fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit>
}

/** Native authorization/admission components are proven; real package replacement is a separate gate. */
internal class DesktopLinuxInstaller(private val stateDirectory: Path,
    private val correlations: DesktopInstallCorrelationJournal = DesktopInstallCorrelationJournal(stateDirectory),
    private val isLinux: () -> Boolean = { System.getProperty("os.name").startsWith("Linux", true) },
) : DesktopLinuxInstallAdapter {
    private var pending: DesktopPreparedInstall? = null

    override fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> = runCatching { correlations.recoverAll() }

    override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> = runCatching {
        require(receipt.phase.terminal)
        val recovered = correlations.recoverAll().single { it.binding?.correlation == correlation }
        require(recovered.binding?.jobId == receipt.jobId && recovered.receipt == receipt)
        pending?.let { require(it.jobId == receipt.jobId); it.close() }
        pending = null
    }

    override suspend fun prepare(packageFile: Path, asset: UpdateAsset,
        correlation: DesktopInstallCorrelation,
        frontend: DesktopFrontendProcessIdentity?,
        onCancellationConfirmed: () -> Unit,
    ): Result<DesktopPreparedInstall> = withContext(Dispatchers.IO) {
        if (pending != null) return@withContext Result.failure(IllegalStateException("BUSY"))
        if (!isLinux())
            return@withContext Result.failure(IllegalStateException("UNSUPPORTED"))
        var watcher: Process? = null
        var coordinator: Process? = null
        var coordinatorAttempted = false
        var reader: DesktopInstallJobStore.Reader? = null
        var copiedChannel: FileChannel? = null
        val senderExecutor = Executors.newSingleThreadExecutor { Thread(it, "linux-install-input").also { thread -> thread.isDaemon = true } }
        try {
            correlations.requireNew(correlation)
            val pid = ProcessHandle.current().pid()
            val uid = (Files.getAttribute(Path.of("/proc/$pid"), "unix:uid") as Number).toLong()
            requireLinuxInstallAuthorization(uid, Files.isExecutable(Path.of("/usr/bin/pkexec")))
            val packageType = asset.packageType.wireName
            check(packageType in setOf("deb", "rpm", "arch-bundle")) { "UNSUPPORTED" }
            val home = userHome(uid)
            val jobId = UUID.randomUUID().toString()
            val input = home.resolve(".local/state/vpn-control-install-inputs").resolve(jobId)
            createPrivateAncestry(input, uid)
            val copied = input.resolve("package.$packageType")
            val digest = MessageDigest.getInstance("SHA-256")
            var size = 0L
            val output = FileChannel.open(copied, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            copiedChannel = output
            run {
                Files.newInputStream(packageFile, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { source ->
                    val bytes = ByteArray(8192)
                    while (true) {
                        val count = source.read(bytes)
                        if (count < 0) break
                        check(size + count <= asset.sizeBytes) { "INVALID_ARGUMENT" }
                        val buffer = ByteBuffer.wrap(bytes, 0, count)
                        while (buffer.hasRemaining()) output.write(buffer)
                        digest.update(bytes, 0, count)
                        size += count
                    }
                }
                check(size == asset.sizeBytes && digest.digest().joinToString("") { "%02x".format(it) } == asset.sha256) { "INVALID_ARGUMENT" }
                output.force(true)
                output.position(0)
            }
            val launcher = Files.readSymbolicLink(Path.of("/proc/$pid/exe")).toString()
            val request = DesktopLinuxInstallRequest(jobId, pid, linuxInstallProcessStart(pid), uid, packageType,
                asset.sha256, size, copied.toString(), launcher, stateDirectory.toAbsolutePath().normalize().toString(),
                frontend?.pid ?: 0, frontend?.let { linuxInstallProcessStart(it.pid) } ?: 0)
            frontend?.let { check(it.isStillSameProcess()) { "CONFLICT" } }
            linuxInstallPublishRecord(input.resolve("request"), request.encode())
            fun receiptReader(): DesktopInstallJobStore.Reader = reader ?:
                DesktopInstallJobStore.production().open(jobId).also { reader = it }
            val receiptPrepared = DesktopReceiptPreparedInstall(jobId,
                readReceipt = { receiptReader().read() },
                publishCommit = { requireNotNull(coordinator).outputStream.let { it.write("$jobId\n".encodeToByteArray()); it.flush() } },
                requestCancellation = { receiptReader().requestCancellation() },
                release = { try { reader?.close() } finally { coordinator?.outputStream?.close() } },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            val prepared = DesktopLinuxUnstartedCancellation(receiptPrepared,
                canProveNotStarted = {
                    // Process is the exact original pkexec child, not a PID
                    // rediscovery. Its fixed command cannot emit 126 or 127.
                    val authorizationExit = coordinator?.takeUnless { it.isAlive }?.exitValue()
                    if (!coordinatorAttempted || authorizationExit in setOf(126, 127)) watcher?.takeIf { it.isAlive }?.let {
                        // This exact original-user watcher cannot install anything without a
                        // coordinator's protected receipt. Never stop a coordinator/package manager.
                        it.destroy(); it.waitFor(5, TimeUnit.SECONDS)
                    }
                    linuxInstallDefinitelyNotStarted(coordinatorAttempted, watcher?.isAlive, authorizationExit)
                },
                recordNotStarted = { correlations.markNotStarted(correlation, jobId) },
                onCancellationConfirmed = { pending = null; onCancellationConfirmed() },
            )
            // Immutable identifiers are durable before either process can exist. Recovery only
            // reads protected receipts; an interrupted launch is never replayed from this record.
            correlations.record(correlation, jobId)
            pending = prepared
            watcher = ProcessBuilder(DesktopLinuxCapturedInstallWorker.watcherArguments(jobId, pid))
                .redirectError(ProcessBuilder.Redirect.DISCARD).start()
            watcher.outputStream.use { it.write(request.encode()) }
            val watcherDeadline = System.nanoTime() + 30_000_000_000L
            val readyBytes = ByteArrayOutputStream()
            while (readyBytes.toByteArray().count { it == '\n'.code.toByte() } < 3) {
                check(watcher.isAlive) { "UNAVAILABLE" }
                check(System.nanoTime() < watcherDeadline) { "OUTCOME_UNKNOWN" }
                val available = watcher.inputStream.available()
                if (available > 0) {
                    readyBytes.write(watcher.inputStream.readNBytes(minOf(available, 257 - readyBytes.size())))
                    check(readyBytes.size() <= 256) { "INVALID_ARGUMENT" }
                }
                delay(50)
            }
            val ready = readyBytes.toByteArray().decodeToString(throwOnInvalidSequence = true)
            check(ready == "$jobId\n${watcher.pid()}\n${linuxInstallProcessStart(watcher.pid())}\n") { "CONFLICT" }
            coordinatorAttempted = true
            coordinator = ProcessBuilder(listOf("/usr/bin/pkexec", "--disable-internal-agent") + DesktopLinuxCapturedInstallWorker.arguments(jobId, pid))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            val authorizationDeadline = System.nanoTime() + 180_000_000_000L
            while (reader == null) {
                try { receiptReader() }
                catch (missing: NoSuchFileException) {
                    check(coordinator.isAlive) {
                        linuxAuthorizationExitCode(coordinator.exitValue()).name
                    }
                    check(System.nanoTime() < authorizationDeadline) { "OUTCOME_UNKNOWN" }
                    delay(50)
                }
            }
            while (true) {
                val first = try { receiptReader().read() } catch (_: NoSuchFileException) {
                    check(System.nanoTime() < authorizationDeadline) { "OUTCOME_UNKNOWN" }; delay(50); continue
                }
                check(first.phase == DesktopInstallJobPhase.PREPARING) { first.code.name }
                break
            }
            val target = coordinator.outputStream
            val sender = CompletableFuture.runAsync({ linuxInstallWritePayload(target, request.encode(), output, size) }, senderExecutor)
            while (!sender.isDone) delay(50)
            try { sender.join() } catch (failure: java.util.concurrent.CompletionException) { throw (failure.cause ?: failure) }
            receiptPrepared.awaitAuthorization().getOrThrow()
            check(watcher.isAlive) { "UNAVAILABLE" }
            Result.success(prepared)
        } catch (cancelled: CancellationException) {
            // Root input readers observe the protected cancel byte while a producer may be blocked on its pipe.
            val active = pending
            if (active != null) {
                val confirmed = withContext(NonCancellable) { active.cancel() }
                if (confirmed.isSuccess) active.close()
                else throw DesktopInstallPreparationFailure(active, IllegalStateException("OUTCOME_UNKNOWN", cancelled))
            }
            throw cancelled
        } catch (failure: Exception) {
            var reported = failure
            if (!coordinatorAttempted) pending?.let { active ->
                val retired = active.cancel()
                if (retired.isSuccess) active.close()
                else reported = IllegalStateException("OUTCOME_UNKNOWN", retired.exceptionOrNull())
            }
            // Only the reserved authorization exits can prove a launched attempt
            // did not start. All other missing receipts retain the original job.
            pending?.let { Result.failure(DesktopInstallPreparationFailure(it, reported)) } ?: Result.failure(reported)
        } finally {
            copiedChannel?.close()
            senderExecutor.shutdownNow()
        }
    }

    private fun userHome(uid: Long): Path {
        val process = ProcessBuilder("/usr/bin/getent", "passwd", uid.toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        process.outputStream.close()
        if (!process.waitFor(5, TimeUnit.SECONDS)) { process.destroyForcibly(); error("UNAVAILABLE") }
        check(process.exitValue() == 0) { "UNAVAILABLE" }
        val line = process.inputStream.use { it.readNBytes(4097) }
        require(line.size <= 4096)
        val fields = line.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').split(':')
        require(fields.size == 7 && fields[2] == uid.toString())
        return Path.of(fields[5]).also { require(it.isAbsolute && it.normalize() == it) }
    }

    private fun createPrivateAncestry(directory: Path, uid: Long) {
        var current = directory.root
        for (component in directory) {
            current = current.resolve(component)
            try { Files.createDirectory(current, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))) }
            catch (_: FileAlreadyExistsException) { }
            require(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS))
            val owner = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
            val mode = (Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
            require(owner in setOf(0L, uid) && mode and 0x12 == 0)
        }
        require((Files.getAttribute(directory, "unix:uid") as Number).toLong() == uid)
        require(Files.getPosixFilePermissions(directory) == PosixFilePermissions.fromString("rwx------"))
    }
}

/** Permission prerequisites are user interaction, not a runtime failure or an unknown wire code. */
internal fun requireLinuxInstallAuthorization(uid: Long, pkexecAvailable: Boolean) {
    check(uid > 0 && pkexecAvailable) { "INTERACTION_REQUIRED" }
}

/** Only reserved pkexec authorization exits can establish non-start after an attempted launch.
 * The caller must still publish the exact journal disposition after checking protected receipt absence.
 */
internal fun linuxInstallDefinitelyNotStarted(coordinatorAttempted: Boolean, watcherAlive: Boolean?,
    authorizationExit: Int? = null): Boolean =
    (!coordinatorAttempted || authorizationExit in setOf(126, 127)) && watcherAlive != true

internal class DesktopLinuxUnstartedCancellation(
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
            // Journal verifies the protected receipt is genuinely missing, not inaccessible.
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

internal fun linuxInstallWritePayload(output: OutputStream, request: ByteArray, source: ReadableByteChannel, size: Long) {
    require(request.size in 1..16384 && size > 0)
    output.write("%06d\n".format(java.util.Locale.ROOT, request.size).encodeToByteArray())
    output.write(request)
    val buffer = ByteBuffer.allocate(8192)
    var sent = 0L
    while (sent < size) {
        check(!Thread.currentThread().isInterrupted) { "CANCELLED" }
        buffer.clear().limit(minOf(buffer.capacity().toLong(), size - sent).toInt())
        val count = source.read(buffer)
        check(count > 0) { "INVALID_ARGUMENT" }
        output.write(buffer.array(), 0, count)
        sent += count
    }
    buffer.clear().limit(1)
    check(source.read(buffer) == -1) { "INVALID_ARGUMENT" }
    output.flush()
}

internal fun linuxInstallProcessStart(pid: Long): Long {
    require(pid in 1..Int.MAX_VALUE)
    val stat = Files.readString(Path.of("/proc/$pid/stat"))
    return parseLinuxInstallProcessStart(stat)
}

internal fun parseLinuxInstallProcessStart(stat: String): Long {
    require(stat.length <= 8192 && stat.contains(") "))
    return stat.substringAfterLast(") ").split(' ')[19].toLong().also { require(it > 0) }
}

/** Flush a private sibling, then link once: Linux never replaces an existing command record. */
internal fun linuxInstallPublishRecord(target: Path, bytes: ByteArray) {
    require(target.fileName.toString() in setOf("request", "commit") && bytes.size <= 16384)
    val temporary = target.resolveSibling("record-${UUID.randomUUID()}.tmp")
    try {
        FileChannel.open(temporary, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { output ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) output.write(buffer)
            output.force(true)
        }
        Files.createLink(target, temporary)
        Files.delete(temporary)
        FileChannel.open(target.parent, StandardOpenOption.READ).use { it.force(true) }
    } finally { Files.deleteIfExists(temporary) }
}

internal fun linuxAuthorizationExitCode(exit: Int): ControlCode = if (exit == 126) ControlCode.CANCELLED else ControlCode.UNAVAILABLE
