package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.runBlocking

/** Protected provider transfer state only. Domain guards and retries stay in the owner ledger. */
internal class AndroidControlDocuments(
    val controllerId: String,
    spool: () -> ControlTransferSpool,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val capacity: Int = 32,
    private val idleMillis: Long = 300_000,
) : AutoCloseable {
    private val store = ControlTransferStore(controllerId, spool, { UUID.randomUUID().toString() },
        clock, capacity = capacity * 2, idleMillis = idleMillis)
    private class Entry(val uid: Int, val context: String, val input: ControlTransferManifest, var touched: Long) {
        var phase = "uploading"
        var sealed: ControlTransferManifest? = null
        var output: ControlTransferManifest? = null
    }
    private val entries = mutableMapOf<String, Entry>()
    private var closed = false

    @Synchronized fun begin(uid: Int, context: String): ControlTransferManifest {
        AndroidControlAccess.opaqueId(context)
        prune()
        check(!closed) { "UNAVAILABLE" }
        entries.values.firstOrNull { it.uid == uid && it.context == context }?.let {
            it.touched = clock()
            return it.sealed ?: it.input
        }
        check(entries.size < capacity) { "BUSY" }
        val input = runBlocking { store.begin(binding(uid, context, false), context) }
        entries[input.id] = Entry(uid, context, input, clock())
        return input
    }

    @Synchronized fun append(uid: Int, id: String, offset: Long, bytes: ByteArray): ControlTransferManifest {
        val entry = entry(uid, id)
        check(entry.phase == "uploading") { "CONFLICT" }
        return runBlocking { store.append(binding(entry, false), id, offset, bytes) }
    }

    @Synchronized fun seal(uid: Int, id: String, count: Long, hash: String): ControlTransferManifest {
        val entry = entry(uid, id)
        check(entry.phase == "uploading" || entry.phase == "sealed") { "CONFLICT" }
        val manifest = runBlocking { store.seal(binding(entry, false), id, count, hash) }
        entry.sealed = manifest
        entry.phase = "sealed"
        return manifest
    }

    /** Claim before launching a job, so concurrent submit retries cannot launch two readers. */
    @Synchronized fun claim(uid: Int, id: String): Input? {
        val entry = entry(uid, id)
        if (entry.phase in setOf("pending", "complete", "failed")) return null
        check(entry.phase == "sealed") { "CONFLICT" }
        val consumer = runBlocking { store.acquire(binding(entry, false), id) }
        entry.phase = "pending"
        return Input(consumer)
    }

    class Input internal constructor(private val consumer: ControlTransferStore.Consumer) : AutoCloseable {
        fun stream(): java.io.InputStream = object : java.io.InputStream() {
            private var offset = 0L
            override fun read(): Int {
                val byte = ByteArray(1)
                return if (read(byte, 0, 1) < 0) -1 else byte[0].toInt() and 255
            }
            override fun read(output: ByteArray, start: Int, length: Int): Int {
                require(start >= 0 && length >= 0 && start <= output.size && length <= output.size - start)
                if (length == 0) return 0
                if (offset == consumer.manifest.byteCount) return -1
                val chunk = runBlocking { consumer.read(offset,
                    minOf(65536L, length.toLong(), consumer.manifest.byteCount - offset).toInt()) }
                try { chunk.copyInto(output, start); offset += chunk.size; return chunk.size }
                finally { chunk.fill(0) }
            }
            override fun close() = this@Input.close()
        }
        fun bytes(): ByteArray {
            val output = ByteArray(Math.toIntExact(consumer.manifest.byteCount))
            try {
                var offset = 0
                while (offset < output.size) {
                    val chunk = runBlocking { consumer.read(offset.toLong(), minOf(65536, output.size - offset)) }
                    try { chunk.copyInto(output, offset); offset += chunk.size } finally { chunk.fill(0) }
                }
                return output
            } catch (error: Exception) { output.fill(0); throw error }
        }
        override fun close() = runBlocking { consumer.close() }
        override fun toString() = "AndroidControlDocumentInput(<redacted>)"
    }

    @Synchronized fun complete(uid: Int, id: String, response: ByteArray) = publish(uid, id) { it.write(response) }

    @Synchronized fun complete(uid: Int, id: String, response: ControlResult) = publish(uid, id) { stream ->
        java.io.OutputStreamWriter(stream, Charsets.UTF_8).buffered(8192).use { writer ->
            ControlDocumentCodec.writeResult(response, writer)
        }
    }

    @Synchronized fun complete(uid: Int, id: String, response: AndroidControlDocumentResponse) = publish(uid, id) { stream ->
        java.io.OutputStreamWriter(stream, Charsets.UTF_8).buffered(8192).use(response::writeTo)
    }

    private fun publish(uid: Int, id: String, write: (java.io.OutputStream) -> Unit) {
        val entry = entry(uid, id)
        check(entry.phase == "pending") { "CONFLICT" }
        val binding = binding(entry, true)
        var output: ControlTransferManifest? = null
        val buffer = ByteArray(65536)
        var published = false
        try {
            var manifest = runBlocking { store.begin(binding, entry.context) }
            output = manifest
            var offset = 0L
            var used = 0
            val hash = MessageDigest.getInstance("SHA-256")
            val stream = object : java.io.OutputStream() {
                override fun write(value: Int) {
                    buffer[used++] = value.toByte()
                    if (used == buffer.size) flush()
                }
                override fun write(bytes: ByteArray, start: Int, count: Int) {
                    require(start >= 0 && count >= 0 && start <= bytes.size - count)
                    var cursor = start
                    var remaining = count
                    while (remaining > 0) {
                        val take = minOf(remaining, buffer.size - used)
                        bytes.copyInto(buffer, used, cursor, cursor + take)
                        used += take; cursor += take; remaining -= take
                        if (used == buffer.size) flush()
                    }
                }
                override fun flush() {
                    if (used == 0) return
                    val chunk = buffer.copyOf(used)
                    try {
                        manifest = runBlocking { store.append(binding, manifest.id, offset, chunk) }
                        hash.update(chunk)
                        offset += chunk.size
                        used = 0
                    } finally { chunk.fill(0) }
                }
                override fun close() = flush()
            }
            write(stream)
            stream.flush()
            output = runBlocking { store.seal(binding, manifest.id, offset, hash.digest().joinToString("") { "%02x".format(it) }) }
            entry.output = output
            entry.phase = "complete"
            published = true
            runBlocking { store.discard(binding(entry, false), id) }
        } finally {
            buffer.fill(0)
            if (!published) {
                output?.let { runCatching { runBlocking { store.discard(binding, it.id) } } }
                entry.phase = "failed"
            }
        }
    }

    @Synchronized fun failed(uid: Int, id: String) {
        val entry = entry(uid, id)
        if (entry.phase == "pending") entry.phase = "failed"
    }

    @Synchronized fun state(uid: Int, id: String): String = entry(uid, id).phase

    @Synchronized fun result(uid: Int, id: String): ControlTransferManifest {
        val entry = entry(uid, id)
        check(entry.phase != "failed") { "OUTCOME_UNKNOWN" }
        check(entry.phase == "complete") { "UNAVAILABLE" }
        return requireNotNull(entry.output)
    }

    @Synchronized fun read(uid: Int, id: String, offset: Long, length: Int): ControlTransferChunk {
        val entry = entry(uid, id)
        val output = result(uid, id)
        return ControlTransferChunk(output.id, offset,
            runBlocking { store.read(binding(entry, true), output.id, offset, length) })
    }

    @Synchronized fun discard(uid: Int, id: String) {
        AndroidControlAccess.opaqueId(id)
        prune()
        val entry = entries[id] ?: return
        if (entry.uid != uid) throw SecurityException("PERMISSION_DENIED")
        check(entry.phase != "pending") { "BUSY" }
        erase(id, entry)
    }

    private fun entry(uid: Int, id: String): Entry {
        AndroidControlAccess.opaqueId(id)
        prune()
        val entry = entries[id] ?: error("NOT_FOUND")
        if (entry.uid != uid) throw SecurityException("PERMISSION_DENIED")
        entry.touched = clock()
        return entry
    }
    private fun binding(entry: Entry, result: Boolean) = binding(entry.uid, entry.context, result)
    private fun binding(uid: Int, context: String, result: Boolean) = ControlTransferBinding(controllerId, "uid:$uid",
        if (result) ControlTransferPurpose.RESPONSE_DOCUMENT else ControlTransferPurpose.COMMAND_DOCUMENT, context)
    private fun prune() {
        entries.toMap().forEach { (id, entry) -> if (clock() - entry.touched >= idleMillis) erase(id, entry) }
        runBlocking { store.prune() }
    }
    private fun erase(id: String, entry: Entry) {
        runBlocking {
            store.discard(binding(entry, false), id)
            entry.output?.let { store.discard(binding(entry, true), it.id) }
        }
        entries.remove(id)
    }
    @Synchronized override fun close() {
        closed = true
        entries.clear()
        runBlocking { store.close() }
    }
}
