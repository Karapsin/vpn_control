package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** Fixed metadata for the authenticated helper pipe. Encoding neither opens paths nor starts work. */
internal object DesktopWindowsRuntimeResourceProtocol {
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
