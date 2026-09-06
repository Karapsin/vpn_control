package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Transport storage only: no configuration mutation, revision admission or operation replay. */
class ControlTransferStore(
    private val ownerId: String,
    private val createSpool: () -> ControlTransferSpool,
    private val newId: () -> String,
    private val clockMillis: () -> Long,
    private val capacity: Int = 32,
    private val idleMillis: Long = 300_000,
    private val consumerCapacity: Int = 32,
) {
    private class Entry(val binding: ControlTransferBinding, val requestId: String, val spool: ControlTransferSpool, var touched: Long) {
        var size = 0L
        var hash: String? = null
        var utf8 = Utf8()
        var retired = false
        var broken = false
        val consumers = mutableSetOf<Any>()
    }
    private val lock = Mutex()
    private val entries = mutableMapOf<String, Entry>()
    private var closed = false
    init { require(ownerId.isNotBlank() && capacity > 0 && idleMillis > 0 && consumerCapacity > 0) }

    suspend fun begin(binding: ControlTransferBinding, requestId: String): ControlTransferManifest = lock.withLock {
        validate(binding)
        if (closed) fail(ControlCode.UNAVAILABLE)
        valid(requestId.isNotBlank() && requestId.length <= 128)
        pruneLocked()
        entries.entries.firstOrNull { it.value.binding == binding && it.value.requestId == requestId && !it.value.retired }
            ?.let { it.value.touched = now(); return@withLock manifest(it.key, it.value) }
        if (entries.size >= capacity) fail(ControlCode.BUSY)
        val id = newId(); validId(id)
        if (id in entries) fail(ControlCode.CONFLICT)
        val spool = try { createSpool() } catch (_: Exception) { fail(ControlCode.PERSISTENCE_FAILED) }
        Entry(binding, requestId, spool, now()).also { entries[id] = it }.let { manifest(id, it) }
    }

    suspend fun append(binding: ControlTransferBinding, id: String, offset: Long, bytes: ByteArray): ControlTransferManifest = lock.withLock {
        val e = entry(binding, id)
        valid(offset >= 0 && bytes.size in 1..ControlTransferLimits.CHUNK_BYTES)
        if (e.hash != null) fail(ControlCode.CONFLICT)
        val copy = bytes.copyOf()
        try {
            if (offset < e.size) {
                if (copy.size.toLong() > e.size - offset) fail(ControlCode.CONFLICT)
                val prior = io(id, e) { e.spool.read(offset, copy.size) }
                val same = prior.contentEquals(copy); prior.fill(0)
                if (!same) fail(ControlCode.CONFLICT)
            } else {
                if (offset != e.size || e.size > Long.MAX_VALUE - copy.size) fail(ControlCode.CONFLICT)
                val next = e.utf8.copy()
                copy.forEach { next.accept(it.toInt() and 255) }
                io(id, e) { e.spool.append(copy) }
                e.utf8 = next
                e.size += copy.size
            }
            e.touched = now()
            manifest(id, e)
        } finally { copy.fill(0) }
    }

    suspend fun seal(binding: ControlTransferBinding, id: String, byteCount: Long, sha256: String): ControlTransferManifest = lock.withLock {
        val e = entry(binding, id)
        valid(byteCount >= 0 && HASH.matches(sha256))
        if (byteCount != e.size || !e.utf8.complete) fail(ControlCode.INVALID_ARGUMENT)
        val hash = e.hash ?: io(id, e) { e.spool.sha256().also { check(HASH.matches(it)) } }
        if (hash != sha256) fail(ControlCode.CONFLICT)
        e.hash = hash
        e.touched = now()
        manifest(id, e)
    }

    suspend fun read(binding: ControlTransferBinding, id: String, offset: Long, length: Int): ByteArray = lock.withLock {
        val e = entry(binding, id)
        readLocked(id, e, offset, length).also { e.touched = now() }
    }

    suspend fun acquire(binding: ControlTransferBinding, id: String): Consumer = lock.withLock {
        val e = entry(binding, id)
        if (e.hash == null) fail(ControlCode.CONFLICT)
        if (e.consumers.size >= consumerCapacity) fail(ControlCode.BUSY)
        val token = Any(); e.consumers.add(token); e.touched = now()
        Consumer(manifest(id, e), { offset, length -> lock.withLock {
            if (entries[id] !== e || token !in e.consumers || e.broken) fail(ControlCode.NOT_FOUND)
            readLocked(id, e, offset, length)
        } }, { lock.withLock {
            e.consumers.remove(token)
            if (e.retired && e.consumers.isEmpty() && entries[id] === e) erase(id, e)
        } })
    }

    /** Authenticated missing IDs are idempotent; existing other-principal IDs never grant access. */
    suspend fun discard(binding: ControlTransferBinding, id: String) = lock.withLock {
        validate(binding); validId(id)
        val e = entries[id] ?: return@withLock
        authorize(binding, e)
        e.retired = true
        if (e.consumers.isEmpty()) erase(id, e)
    }

    suspend fun prune() = lock.withLock { pruneLocked() }
    suspend fun hasRetainedTransfers(): Boolean = lock.withLock { pruneLocked(); entries.isNotEmpty() }

    /** Owner shutdown must first drain consumers; this never destroys an active consumer's data. */
    suspend fun close() = lock.withLock {
        closed = true
        entries.toMap().forEach { (id, e) -> e.retired = true; if (e.consumers.isEmpty()) erase(id, e) }
    }

    class Consumer internal constructor(
        val manifest: ControlTransferManifest,
        private val reader: suspend (Long, Int) -> ByteArray,
        private val release: suspend () -> Unit,
    ) {
        suspend fun read(offset: Long, length: Int): ByteArray = reader(offset, length)
        suspend fun close() = release()
        override fun toString() = "ControlTransferConsumer(<redacted>)"
    }

    private fun entry(binding: ControlTransferBinding, id: String): Entry {
        validate(binding); validId(id)
        val e = entries[id] ?: fail(ControlCode.NOT_FOUND)
        authorize(binding, e)
        if (now() - e.touched >= idleMillis) {
            e.retired = true
            if (e.consumers.isEmpty()) erase(id, e)
        }
        if (e.retired) fail(ControlCode.NOT_FOUND)
        return e
    }
    private fun readLocked(id: String, e: Entry, offset: Long, length: Int): ByteArray {
        if (e.hash == null) fail(ControlCode.CONFLICT)
        valid(offset >= 0 && offset <= e.size && length in 0..ControlTransferLimits.CHUNK_BYTES && length.toLong() <= e.size - offset)
        return io(id, e) { e.spool.read(offset, length).also { check(it.size == length) } }
    }
    private fun pruneLocked() {
        val time = now()
        entries.toMap().forEach { (id, e) ->
            if (time - e.touched >= idleMillis) e.retired = true
            if (e.retired && e.consumers.isEmpty()) erase(id, e)
        }
    }
    private fun erase(id: String, e: Entry) {
        try { e.spool.erase(); entries.remove(id) } catch (_: Exception) { fail(ControlCode.PERSISTENCE_FAILED) }
    }
    private inline fun <T> io(id: String, e: Entry, operation: () -> T): T = try { operation() } catch (_: Exception) {
        e.retired = true
        e.broken = true
        if (e.consumers.isEmpty()) runCatching { erase(id, e) }
        fail(ControlCode.PERSISTENCE_FAILED)
    }
    private fun validate(binding: ControlTransferBinding) {
        if (binding.ownerId != ownerId) fail(ControlCode.CONFLICT)
        valid(binding.principal.isNotBlank() && binding.principal.length <= 256)
    }
    private fun authorize(binding: ControlTransferBinding, e: Entry) {
        if (binding != e.binding) fail(ControlCode.PERMISSION_DENIED)
    }
    private fun now() = clockMillis().also { check(it >= 0) }
    private fun manifest(id: String, e: Entry) = ControlTransferManifest(id, e.size, e.hash)
    private fun validId(id: String) = valid(ID.matches(id))
    private fun valid(value: Boolean) { if (!value) fail(ControlCode.INVALID_ARGUMENT) }
    private fun fail(code: ControlCode): Nothing = throw ControlProtocolException(code)

    /** Strict RFC3629 state, including overlong encodings, surrogates and >U+10FFFF. */
    private data class Utf8(var remaining: Int = 0, var lower: Int = 128, var upper: Int = 191) {
        val complete get() = remaining == 0
        fun accept(byte: Int) {
            if (remaining != 0) {
                if (byte !in lower..upper) throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
                remaining--; lower = 128; upper = 191
            } else when (byte) {
                in 0..127 -> Unit
                in 194..223 -> remaining = 1
                in 224..239 -> { remaining = 2; if (byte == 224) lower = 160; if (byte == 237) upper = 159 }
                in 240..244 -> { remaining = 3; if (byte == 240) lower = 144; if (byte == 244) upper = 143 }
                else -> throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
            }
        }
    }
    companion object {
        private val ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        private val HASH = Regex("[0-9a-f]{64}")
    }
}
