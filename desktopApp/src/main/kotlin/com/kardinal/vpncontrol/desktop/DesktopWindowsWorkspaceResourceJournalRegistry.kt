package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.nio.file.Path

/** Only explicit resource correlations survive owner loss. No record is executable work. */
internal class DesktopWindowsWorkspaceResourceJournalRegistry(
    workspace: Path,
    private val currentScope: () -> DesktopWindowsRuntimeResourceScope,
    private val storage: DesktopWindowsResourceCorrelationStorage =
        DesktopWindowsResourceCorrelationFiles(workspace, currentScope),
) : DesktopWindowsRuntimeResourceJournalRegistry {
    @Synchronized override fun retain(job: DesktopWindowsRuntimeResourceJob) {
        val current = currentScope()
        check(sameScope(current, job.scope) && current.controllerId == job.scope.controllerId) { "CONFLICT" }
        val existing = records(current)
        val bytes = encode(job)
        existing[job.jobId]?.let { check(encode(it).contentEquals(bytes)) { "CONFLICT" }; return }
        check(existing.size < MAX_PENDING) { "BUSY" }
        storage.publish(job.jobId, bytes)
        // A lost publication response remains recoverable by this exact job identity.
        check(storage.readAll()[job.jobId]?.contentEquals(bytes) == true) { "PERSISTENCE_FAILED" }
    }

    @Synchronized override fun pending(scope: DesktopWindowsRuntimeResourceScope): List<DesktopWindowsRuntimeResourceJob> {
        val current = currentScope()
        check(sameScope(current, scope) && current.controllerId == scope.controllerId) { "CONFLICT" }
        return records(current).values.toList()
    }

    @Synchronized override fun reconcile(job: DesktopWindowsRuntimeResourceJob,
        disposition: DesktopWindowsRuntimeResourceJobDisposition) {
        // The native adapter establishes disposition. Neither reading nor a UI request calls this method.
        val current = currentScope()
        check(sameScope(current, job.scope)) { "CONFLICT" }
        val retained = records(current)[job.jobId] ?: return
        val expected = encode(job)
        check(encode(retained).contentEquals(expected)) { "CONFLICT" }
        storage.removeExact(job.jobId, expected)
    }

    private fun records(scope: DesktopWindowsRuntimeResourceScope): Map<String, DesktopWindowsRuntimeResourceJob> {
        val records = storage.readAll()
        check(records.size <= MAX_PENDING) { "BUSY" }
        return records.mapValues { (id, bytes) -> decode(bytes).also {
            check(id == it.jobId && sameScope(scope, it.scope)) { "CONFLICT" }
        } }
    }

    private fun encode(job: DesktopWindowsRuntimeResourceJob): ByteArray {
        val scope = job.scope
        val record = scope.record
        return ControlDocumentCodec.encodeValues(linkedMapOf(
            "schemaVersion" to ControlValue.IntegerValue(2),
            "jobId" to ControlValue.Text(job.jobId), "scopeId" to ControlValue.Text(scope.scopeId),
            "controllerId" to ControlValue.Text(scope.controllerId), "path" to ControlValue.Text(record.path),
            "parentIdentity" to ControlValue.Text(record.parentIdentity), "fileIdentity" to ControlValue.Text(record.fileIdentity),
            "byteCount" to ControlValue.IntegerValue(record.byteCount), "sha256" to ControlValue.Text(record.sha256),
            "nativeOwner" to ControlValue.ObjectValue(linkedMapOf(
                "processId" to ControlValue.IntegerValue(job.nativeOwner.processId),
                "creationFileTime" to ControlValue.IntegerValue(job.nativeOwner.creationFileTime),
                "sid" to ControlValue.Text(job.nativeOwner.sid))),
            "resources" to ControlValue.ArrayValue(job.resources.map { ControlValue.ObjectValue(linkedMapOf(
                "resourceId" to ControlValue.Text(it.resourceId), "kind" to ControlValue.Text(it.kind.name))) }),
        )).encodeToByteArray()
    }

    private fun decode(bytes: ByteArray): DesktopWindowsRuntimeResourceJob {
        val values = ControlDocumentCodec.decodeValues(bytes.decodeToString(throwOnInvalidSequence = true))
        check(values.keys == setOf("schemaVersion", "jobId", "scopeId", "controllerId", "path", "parentIdentity",
            "fileIdentity", "byteCount", "sha256", "nativeOwner", "resources")) { "CONFLICT" }
        check(values["schemaVersion"] == ControlValue.IntegerValue(2)) { "CONFLICT" }
        fun text(key: String) = (values.getValue(key) as ControlValue.Text).value
        val scope = DesktopWindowsRuntimeResourceScope(text("scopeId"), text("controllerId"),
            DesktopWindowsResourceScopeRecord(text("path"), text("parentIdentity"), text("fileIdentity"),
                (values.getValue("byteCount") as ControlValue.IntegerValue).value, text("sha256")))
        val entries = (values.getValue("resources") as ControlValue.ArrayValue).values.map {
            val fields = (it as ControlValue.ObjectValue).values
            check(fields.keys == setOf("resourceId", "kind")) { "CONFLICT" }
            DesktopWindowsRuntimeResourceEntry((fields.getValue("resourceId") as ControlValue.Text).value,
                DesktopWindowsRuntimeResourceKind.valueOf((fields.getValue("kind") as ControlValue.Text).value))
        }
        val owner = (values.getValue("nativeOwner") as ControlValue.ObjectValue).values
        check(owner.keys == setOf("processId", "creationFileTime", "sid")) { "CONFLICT" }
        val nativeOwner = DesktopWindowsRuntimeResourceNativeOwner(
            (owner.getValue("processId") as ControlValue.IntegerValue).value,
            (owner.getValue("creationFileTime") as ControlValue.IntegerValue).value,
            (owner.getValue("sid") as ControlValue.Text).value)
        return DesktopWindowsRuntimeResourceJob(text("jobId"), scope, entries, nativeOwner).also {
            check(encode(it).contentEquals(bytes)) { "CONFLICT" }
        }
    }

    companion object {
        internal const val MAX_PENDING = 8
        private fun sameScope(left: DesktopWindowsRuntimeResourceScope, right: DesktopWindowsRuntimeResourceScope): Boolean {
            val a = left.record; val b = right.record
            return left.scopeId == right.scopeId && a.path == b.path && a.parentIdentity == b.parentIdentity &&
                a.fileIdentity == b.fileIdentity && a.byteCount == b.byteCount && a.sha256 == b.sha256
        }
    }
}

internal interface DesktopWindowsResourceCorrelationStorage {
    fun readAll(): Map<String, ByteArray>
    fun publish(jobId: String, bytes: ByteArray)
    fun removeExact(jobId: String, bytes: ByteArray)
}

/** Pins the ordinary workspace and exact file through validation and conditional deletion. */
private class DesktopWindowsResourceCorrelationFiles(
    workspace: Path,
    private val currentScope: () -> DesktopWindowsRuntimeResourceScope,
) : DesktopWindowsResourceCorrelationStorage {
    private val directory = workspace.toAbsolutePath().normalize()
    private val prefix = ".runtime-resource-job-"

    override fun readAll(): Map<String, ByteArray> = pinned { native, owner, parent ->
        val paths = Files.newDirectoryStream(directory) { it.fileName.toString().startsWith(prefix) }.use {
            it.asSequence().take(DesktopWindowsWorkspaceResourceJournalRegistry.MAX_PENDING + 1).toList()
        }
        check(paths.size <= DesktopWindowsWorkspaceResourceJournalRegistry.MAX_PENDING) { "BUSY" }
        paths.associate { path ->
            val name = path.fileName.toString()
            val id = name.removePrefix(prefix).removeSuffix(".json")
            check(java.util.UUID.fromString(id).toString() == id && name == leaf(id)) { "CONFLICT" }
            val handle = native.open(parent + "\\" + name, WindowsInstallNative.PINNED_READ, false)
            try {
                native.requirePrivateExport(handle, owner)
                id to readComplete(native, handle)
            } finally { native.close(handle) }
        }
    }

    override fun publish(jobId: String, bytes: ByteArray) = pinned { _, _, _ ->
        DesktopPrivateExportWriter.write(directory.resolve(leaf(jobId)).toString(), bytes).getOrThrow()
    }

    override fun removeExact(jobId: String, bytes: ByteArray) = pinned { native, owner, parent ->
        val handle = native.openPrivateCorrelation(parent + "\\" + leaf(jobId))
        try {
            native.requirePrivateExport(handle, owner)
            check(readComplete(native, handle).contentEquals(bytes)) { "CONFLICT" }
            native.delete(handle)
        } finally { native.close(handle) }
    }

    private fun readComplete(native: JnaWindowsInstallNative, handle: WindowsInstallNative.Handle): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var offset = 0L
        while (true) {
            val count = native.readExportChunk(handle, offset, chunk, chunk.size)
            if (count == 0) break
            output.write(chunk, 0, count)
            offset = Math.addExact(offset, count.toLong())
        }
        check(native.inspect(handle).size == offset) { "CONFLICT" }
        return output.toByteArray()
    }

    private fun leaf(id: String): String {
        require(java.util.UUID.fromString(id).toString() == id)
        return "$prefix$id.json"
    }

    private fun <T> pinned(action: (JnaWindowsInstallNative, String, String) -> T): T {
        val native = JnaWindowsInstallNative()
        val owner = JnaWindowsInstallAdmission().currentSid()
        return DesktopWindowsTransferPins.open(directory.toString(), owner, native).use { pins ->
            // Scope proof is revalidated while all ancestry handles deny replacement.
            val scope = currentScope()
            check(Path.of(scope.record.path).parent.toRealPath() == directory.toRealPath()) { "CONFLICT" }
            action(native, owner, native.retainedExportDirectory(pins.parentHandle).trimEnd('\\'))
        }
    }
}
