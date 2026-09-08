package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import com.kardinal.vpncontrol.model.ControlCode

/** Fixed metadata for the authenticated helper pipe. Encoding neither opens paths nor starts work. */
internal object DesktopWindowsRuntimeResourceProtocol {
    /** Decode a status only from the authenticated pipe; malformed terminal evidence stays unknown. */
    fun readStatus(mutable: Boolean, read: (Int) -> ByteArray): DesktopWindowsRuntimeStatus {
        fun integer() = ByteBuffer.wrap(read(4)).order(ByteOrder.LITTLE_ENDIAN).int
        fun byte() = read(1).single().toInt()
        fun text(limit: Int): String {
            val size = integer(); check(size in 0..limit)
            return read(size).decodeToString(throwOnInvalidSequence = true)
        }
        fun terminal(): DesktopWindowsNativeResourceReconciliation {
            check(integer() == 1)
            val jobId = text(36)
            val count = integer(); check(count in 1..65536)
            val entries = List(count) {
                val id = text(36)
                val kind = when (byte()) {
                    0 -> DesktopWindowsRuntimeResourceKind.CACHE
                    1 -> DesktopWindowsRuntimeResourceKind.OUTPUT
                    else -> throw IllegalStateException("INCOMPATIBLE_PROTOCOL")
                }
                val disposition = when (byte()) {
                    0 -> DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF
                    1 -> DesktopWindowsNativeResourceDisposition.PUBLISHED
                    2 -> DesktopWindowsNativeResourceDisposition.PENDING_PUBLICATION
                    3 -> DesktopWindowsNativeResourceDisposition.COMMITTED_CLEANUP_PENDING
                    else -> throw IllegalStateException("INCOMPATIBLE_PROTOCOL")
                }
                val code = when (byte()) {
                    0 -> null
                    1 -> ControlCode.PERSISTENCE_FAILED
                    2 -> ControlCode.PERMISSION_DENIED
                    3 -> ControlCode.CONFLICT
                    4 -> ControlCode.OUTCOME_UNKNOWN
                    else -> throw IllegalStateException("INCOMPATIBLE_PROTOCOL")
                }
                DesktopWindowsNativeResourceResult(id, kind, disposition, code)
            }
            val cleanup = when (byte()) { 0 -> false; 1 -> true; else -> throw IllegalStateException("INCOMPATIBLE_PROTOCOL") }
            return DesktopWindowsNativeResourceReconciliation(jobId, entries, cleanup)
        }
        val alive = byte(); check(alive in 0..1)
        val logSize = integer(); check(logSize in 0..65536)
        val log = read(logSize)
        // The C# broker always sends the bounded final log before terminal resource evidence.
        // A missing/truncated envelope is left to the reconciler as unresolved ownership.
        val reconciliation = if (alive == 0 && mutable) terminal() else null
        return DesktopWindowsRuntimeStatus(alive == 1, log, reconciliation)
    }

    fun writePreparation(job: DesktopWindowsRuntimeResourceJob, resources: List<DesktopWindowsRuntimeResource>,
                         write: (ByteArray, Int, Int) -> Unit) {
        val captured = resources.sortedBy { it.id }
        val expected = job.resources.sortedBy { it.resourceId }
        require(captured.size == expected.size && captured.zip(expected).all { (actual, entry) ->
            actual.id == entry.resourceId && actual.kind == entry.kind
        }) { "CONFLICT" }
        fun bytes(value: ByteArray) {
            var offset = 0
            while (offset < value.size) {
                val count = minOf(65536, value.size - offset)
                write(value, offset, count)
                offset += count
            }
        }
        fun integer(value: Int) = bytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array())
        fun long(value: Long) = bytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array())
        fun text(value: String) {
            val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
            val content = ByteArray(encoded.remaining()).also { encoded.get(it) }
            integer(content.size)
            bytes(content)
        }
        integer(1)
        text(job.jobId)
        text(job.scope.scopeId)
        text(job.scope.controllerId)
        long(job.nativeOwner.processId)
        long(job.nativeOwner.creationFileTime)
        text(job.nativeOwner.sid)
        val proof = job.scope.record
        text(proof.path)
        text(proof.parentIdentity)
        text(proof.fileIdentity)
        long(proof.byteCount)
        text(proof.sha256)
        integer(captured.size)
        for (entry in captured) { text(entry.id); text(entry.kind.name) }
        for (entry in captured) {
            text(entry.destination.path)
            text(entry.destination.parentIdentity)
        }
    }
}
