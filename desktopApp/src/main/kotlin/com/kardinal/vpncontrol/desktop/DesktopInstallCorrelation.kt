package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest

/** Identifiers only: never persist the install command, package path, or control credential. */
internal data class DesktopInstallCorrelation(val controllerId: String, val requestId: String, val operationId: String) {
    init { require(listOf(controllerId, requestId, operationId).all { value ->
        value.isNotBlank() && value.length <= 256 && value.none { it.code < 32 }
    }) }
}

internal enum class DesktopInstallReceiptAuthority { MACHINE, MACOS_USER_LOCAL }

internal data class DesktopInstallCorrelationRecord(
    val correlation: DesktopInstallCorrelation, val jobId: String, val workspaceKey: String,
    val receiptAuthority: DesktopInstallReceiptAuthority = DesktopInstallReceiptAuthority.MACHINE,
) {
    init { require(DesktopInstallJobNames.validJob(jobId) && workspaceKey.matches(Regex("[a-f0-9]{64}"))) }
}

internal data class DesktopInstallCorrelationRecovery(
    val binding: DesktopInstallCorrelationRecord?, val receipt: DesktopInstallJobReceipt?, val code: ControlCode,
    val notStarted: Boolean = false,
    val cleanupCode: ControlCode? = null,
) {
    val blocksInstallation get() = binding != null && !notStarted && receipt?.phase?.terminal != true
}

/**
 * Immutable workspace-owner journal. Call record from the owner's serialized mutation lane.
 * Entries correlate protected receipts; they never authorize installation or replay a worker.
 * A crash after journal publication but before worker creation deliberately remains unknown.
 */
internal class DesktopInstallCorrelationJournal(
    workspace: Path,
    private val terminalHistoryLimit: Int = 32,
    private val readBoundReceipt: ((DesktopInstallCorrelationRecord) -> DesktopInstallJobReceipt)? = null,
    private val readProtectedReceipt: (String) -> DesktopInstallJobReceipt = { job ->
        DesktopInstallJobStore.production().open(job).use { it.read() }
    },
) {
    private val directory = DesktopWorkspacePaths.resolve(workspace.toString())
    private val workspaceKey = hash(directory.toString())
    init { require(terminalHistoryLimit in 1 until MAX_RECORDS) }

    @Synchronized fun record(correlation: DesktopInstallCorrelation, jobId: String,
        receiptAuthority: DesktopInstallReceiptAuthority = DesktopInstallReceiptAuthority.MACHINE): DesktopInstallCorrelationRecord {
        val requested = DesktopInstallCorrelationRecord(correlation, jobId, workspaceKey, receiptAuthority)
        val existing = records()
        existing.firstOrNull { it.correlation == correlation }?.let {
            require(it == requested) { ControlCode.CONFLICT.name }
            return it
        }
        require(existing.none { conflicts(it, requested) }) { ControlCode.CONFLICT.name }
        pruneTerminals(existing)
        require(records().size < MAX_RECORDS) { ControlCode.BUSY.name }
        Files.createDirectories(directory)
        DesktopPrivateExportWriter.write(path(requested).toString(), encode(requested)).getOrElse {
            throw IllegalStateException(ControlCode.PERSISTENCE_FAILED.name, it)
        }
        return requested
    }

    /**
     * Adapter-only proof: no coordinator was launched, or the exact authorization process
     * confirmed rejection before executing it. Never records authorization or installation.
     * An existing/inaccessible protected receipt cannot be overridden by local evidence.
     */
    @Synchronized fun markNotStarted(correlation: DesktopInstallCorrelation, jobId: String,
        code: ControlCode = ControlCode.CANCELLED) {
        require(code in NOT_STARTED_CODES)
        val binding = requireNotNull(records().singleOrNull { it.correlation == correlation })
        require(binding.jobId == jobId)
        try {
            readReceipt(binding)
            error("Protected installation already exists")
        } catch (failure: Exception) { if (!missingReceipt(failure)) throw failure }
        val marker = dispositionPath(binding)
        if (Files.exists(marker, NOFOLLOW_LINKS)) {
            require(requireNotStarted(binding) == code) { ControlCode.CONFLICT.name }
            return
        }
        DesktopPrivateExportWriter.write(marker.toString(), encode(binding, notStarted = true, code = code)).getOrThrow()
    }

    /** Corrupt, copied, insecure, or over-capacity journals fail closed before consulting any receipt. */
    fun records(): List<DesktopInstallCorrelationRecord> {
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return emptyList()
        val paths = Files.newDirectoryStream(directory) { it.fileName.toString().startsWith(PREFIX) }.use {
            it.asSequence().take(MAX_RECORDS + 1).toList()
        }
        require(paths.size <= MAX_RECORDS)
        val records = paths.map { candidate ->
            decode(readPrivate(candidate)).also {
                require(it.workspaceKey == workspaceKey && path(it) == candidate)
            }
        }
        records.forEachIndexed { index, record -> require(records.take(index).none { conflicts(it, record) }) }
        return records
    }

    fun recover(correlation: DesktopInstallCorrelation): DesktopInstallCorrelationRecovery {
        val binding = records().firstOrNull { it.correlation.controllerId == correlation.controllerId &&
            it.correlation.operationId == correlation.operationId }
            ?: return DesktopInstallCorrelationRecovery(null, null, ControlCode.NOT_FOUND)
        require(binding.correlation == correlation) { ControlCode.CONFLICT.name }
        return inspect(binding)
    }

    fun recoverAll(): List<DesktopInstallCorrelationRecovery> = records().map(::inspect)

    /** Must run before staging or launching: previous identities are queried, never replayed. */
    fun requireNew(correlation: DesktopInstallCorrelation) {
        val previous = recoverAll()
        require(previous.none { it.binding?.correlation?.let { old ->
            old.controllerId == correlation.controllerId &&
                (old.requestId == correlation.requestId || old.operationId == correlation.operationId)
        } == true }) { ControlCode.CONFLICT.name }
        check(previous.none { it.blocksInstallation }) { ControlCode.BUSY.name }
    }

    private fun inspect(binding: DesktopInstallCorrelationRecord): DesktopInstallCorrelationRecovery {
        val receipt = try {
            readReceipt(binding).also { require(it.jobId == binding.jobId) }
        } catch (failure: Exception) {
            if (missingReceipt(failure) && Files.exists(dispositionPath(binding), NOFOLLOW_LINKS)) {
                val code = requireNotStarted(binding)
                return DesktopInstallCorrelationRecovery(binding, null, code, notStarted = true)
            }
            return DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN)
        }
        return DesktopInstallCorrelationRecovery(binding, receipt,
            if (receipt.phase.terminal) receipt.code else ControlCode.ACCEPTED)
    }

    private fun pruneTerminals(existing: List<DesktopInstallCorrelationRecord>) {
        val terminal = existing.filter { !inspect(it).blocksInstallation }
            .sortedBy { Files.getLastModifiedTime(path(it), NOFOLLOW_LINKS).toMillis() }
        terminal.take((terminal.size - terminalHistoryLimit).coerceAtLeast(0)).forEach { binding ->
            // Remove only the verified journal entry, never the protected receipt or job.
            // Delete binding first: a crash may leave an inert disposition, never a live
            // binding whose only cancellation proof was removed.
            Files.delete(path(binding))
            Files.deleteIfExists(dispositionPath(binding))
        }
    }

    private fun dispositionPath(record: DesktopInstallCorrelationRecord) =
        directory.resolve(path(record).fileName.toString().replace(PREFIX, DISPOSITION_PREFIX))

    private fun requireNotStarted(binding: DesktopInstallCorrelationRecord): ControlCode {
        val bytes = readPrivate(dispositionPath(binding))
        require(decode(bytes, notStarted = true) == binding)
        val values = ControlProtocolCodec.decodeValues(bytes.decodeToString(throwOnInvalidSequence = true))
        return dispositionCode(values)
    }

    private fun readPrivate(path: Path): ByteArray {
        require(Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).isRegularFile)
        DesktopControlEndpoint.verifyPermissions(path)
        return Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(MAX_BYTES + 1) }
            .also { require(it.size <= MAX_BYTES) }
    }

    private fun path(record: DesktopInstallCorrelationRecord) = directory.resolve(PREFIX + hash(
        ControlProtocolCodec.encodeValues(mapOf("controllerId" to ControlValue.Text(record.correlation.controllerId),
            "operationId" to ControlValue.Text(record.correlation.operationId)))) + ".json")

    private fun readReceipt(binding: DesktopInstallCorrelationRecord): DesktopInstallJobReceipt {
        readBoundReceipt?.let { return it(binding) }
        require(binding.receiptAuthority == DesktopInstallReceiptAuthority.MACHINE) { "Explicit receipt authority reader required" }
        return readProtectedReceipt(binding.jobId)
    }

    private fun encode(record: DesktopInstallCorrelationRecord, notStarted: Boolean = false,
        code: ControlCode = ControlCode.CANCELLED): ByteArray = ControlProtocolCodec.encodeValues(mapOf(
        "version" to ControlValue.IntegerValue(1), "controllerId" to ControlValue.Text(record.correlation.controllerId),
        "requestId" to ControlValue.Text(record.correlation.requestId), "operationId" to ControlValue.Text(record.correlation.operationId),
        "jobId" to ControlValue.Text(record.jobId), "workspaceKey" to ControlValue.Text(record.workspaceKey),
    ) + (if (record.receiptAuthority != DesktopInstallReceiptAuthority.MACHINE)
        mapOf("receiptAuthority" to ControlValue.Text(record.receiptAuthority.name)) else emptyMap()) +
        (if (notStarted) mapOf("disposition" to ControlValue.Text("NOT_STARTED")) +
            (if (code != ControlCode.CANCELLED) mapOf("code" to ControlValue.Text(code.wireName)) else emptyMap())
            else emptyMap())).encodeToByteArray().also { require(it.size <= MAX_BYTES) }

    private fun decode(bytes: ByteArray, notStarted: Boolean = false): DesktopInstallCorrelationRecord {
        val values = ControlProtocolCodec.decodeValues(bytes.decodeToString(throwOnInvalidSequence = true))
        require(values.keys == setOf("version", "controllerId", "requestId", "operationId", "jobId", "workspaceKey") +
            (if (notStarted) setOf("disposition") else emptySet()) +
            (if (notStarted && "code" in values) setOf("code") else emptySet()) +
            (if ("receiptAuthority" in values) setOf("receiptAuthority") else emptySet()))
        if (notStarted) {
            require(values["disposition"] == ControlValue.Text("NOT_STARTED"))
            dispositionCode(values)
        }
        require(values["version"] == ControlValue.IntegerValue(1))
        fun text(key: String) = (values.getValue(key) as ControlValue.Text).value
        return DesktopInstallCorrelationRecord(DesktopInstallCorrelation(text("controllerId"), text("requestId"), text("operationId")),
            text("jobId"), text("workspaceKey"), if ("receiptAuthority" in values)
                DesktopInstallReceiptAuthority.valueOf(text("receiptAuthority")) else DesktopInstallReceiptAuthority.MACHINE)
    }

    companion object {
        private val NOT_STARTED_CODES = setOf(ControlCode.CANCELLED, ControlCode.PERMISSION_DENIED, ControlCode.INTERACTION_REQUIRED, ControlCode.RUNTIME_FAILED)
        private fun dispositionCode(values: Map<String, ControlValue>): ControlCode {
            if ("code" !in values) return ControlCode.CANCELLED // Existing cancellation markers.
            val code = (values["code"] as? ControlValue.Text)?.value
            return requireNotNull(NOT_STARTED_CODES.singleOrNull { it.wireName == code })
        }
        private const val PREFIX = ".install-correlation-"
        private const val DISPOSITION_PREFIX = ".install-not-started-"
        private const val MAX_BYTES = 4096
        private const val MAX_RECORDS = 256
        private fun hash(value: String) = MessageDigest.getInstance("SHA-256").digest(value.encodeToByteArray())
            .joinToString("") { "%02x".format(it) }
        private fun conflicts(left: DesktopInstallCorrelationRecord, right: DesktopInstallCorrelationRecord) =
            left.jobId == right.jobId || left.correlation.controllerId == right.correlation.controllerId &&
                (left.correlation.requestId == right.correlation.requestId || left.correlation.operationId == right.correlation.operationId)
        private fun missingReceipt(failure: Exception) = failure is java.nio.file.NoSuchFileException ||
            failure is WindowsInstallNativeFailure && failure.code in setOf(2, 3)
    }
}
