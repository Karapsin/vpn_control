package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.kardinal.vpncontrol.data.AndroidNativeString
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import java.io.IOException
import java.lang.ref.PhantomReference
import java.lang.ref.ReferenceQueue
import java.security.MessageDigest
import java.util.RandomAccess

/**
 * Large terminal routing results own private disk snapshots, not old preference
 * strings. Both the value index and UTF16 contents live in the unlinked spool.
 * Expiring a ledger entry cannot close a value still held by an active reader.
 */
internal class AndroidRetainedControlResults(private val createSpool: () -> ControlTransferSpool) : AutoCloseable {
    private val queue = ReferenceQueue<Values>()
    private val leases = mutableSetOf<Lease>()
    // Capture resources stay owned even if publication or their first close fails.
    private val pending = java.util.IdentityHashMap<ControlTransferSpool, Boolean>()
    private var closed = false

    /** Only generated routing results are converted; no command arguments enter here. */
    fun retain(result: ControlResult): ControlResult {
        val original = result.data["direct-domains"] as? ControlValue.ArrayValue ?: return result
        if (original.values is Values || !large(original.values)) return result
        // Prepare the small truthful fallback before any larger allocation or IO.
        val unavailable = result.copy(warnings = result.warnings + "RETAINED_RESULT_STORAGE_UNAVAILABLE")
        val exhausted = unavailable.copy(warnings = unavailable.warnings + "RESOURCE_EXHAUSTED")
        var spool: ControlTransferSpool? = null
        var registered = false
        return try {
            reap()
            spool = synchronized(this) {
                if (closed) throw IOException("Retained result owner is closed")
                createSpool().also { pending[it] = false }
            }
            val values = write(original.values, spool)
            val stored = result.copy(data = result.data + ("direct-domains" to ControlValue.ArrayValue(values)))
            synchronized(this) {
                if (closed) throw IOException("Retained result owner is closed")
                leases += Lease(values, queue, values.resource)
                pending.remove(spool)
                registered = true
            }
            stored
        } catch (_: OutOfMemoryError) {
            // The effect already committed. Retain its exact original data and
            // success; this exceptional fallback makes no bounded-heap claim.
            exhausted
        } catch (_: Exception) {
            unavailable
        } finally {
            if (!registered) spool?.let { owned -> synchronized(this) {
                pending[owned] = true
                try { owned.erase(); pending.remove(owned) } catch (_: Exception) { /* Retry under this owner. */ }
            } }
        }
    }

    @Synchronized fun reap() {
        val pendingIterator = pending.iterator()
        while (pendingIterator.hasNext()) {
            val entry = pendingIterator.next()
            if (entry.value) { entry.key.erase(); pendingIterator.remove() }
        }
        while (true) {
            val lease = queue.poll() as? Lease ?: break
            lease.unreachable = true
        }
        val iterator = leases.iterator()
        while (iterator.hasNext()) {
            val lease = iterator.next()
            if (lease.unreachable) {
                lease.resource.close()
                lease.clear()
                iterator.remove()
            }
        }
    }

    /** Closing an owner deliberately invalidates its outstanding private results. */
    @Synchronized override fun close() {
        closed = true
        val iterator = leases.iterator()
        var failure: Exception? = null
        val pendingIterator = pending.iterator()
        while (pendingIterator.hasNext()) {
            try { pendingIterator.next().key.erase(); pendingIterator.remove() }
            catch (error: Exception) { if (failure == null) failure = error }
        }
        while (iterator.hasNext()) {
            val lease = iterator.next()
            try { lease.resource.close(); lease.clear(); iterator.remove() }
            catch (error: Exception) { if (failure == null) failure = error }
        }
        failure?.let { throw it }
    }

    private class Lease(values: Values, queue: ReferenceQueue<Values>, val resource: Resource) :
        PhantomReference<Values>(values, queue) { var unreachable = false }

    private class Resource(private val spool: ControlTransferSpool, val byteCount: Long) : AutoCloseable {
        private var closed = false
        @Synchronized fun read(offset: Long, count: Int): ByteArray {
            if (closed) throw IOException("Retained result owner is closed")
            if (offset < 0 || offset > byteCount || count !in 0..CHUNK || count.toLong() > byteCount - offset)
                throw IOException("Retained result range is invalid")
            return spool.read(offset, count).also {
                if (it.size != count) { it.fill(0); throw IOException("Retained result length changed") }
            }
        }
        @Synchronized override fun close() {
            if (!closed) { spool.erase(); closed = true }
        }
    }

    private class Values(val resource: Resource, override val size: Int) : AbstractList<ControlValue>(), RandomAccess {
        override fun get(index: Int): ControlValue {
            if (index !in 0 until size) throw IndexOutOfBoundsException()
            val record = resource.read(index.toLong() * INDEX_BYTES, INDEX_BYTES)
            try {
                val offset = longAt(record, 0)
                val count = intAt(record, 8)
                val bytes = count.toLong() * 2
                if (count < 0 || offset < size.toLong() * INDEX_BYTES || offset > resource.byteCount || bytes > resource.byteCount - offset)
                    throw IOException("Retained result index is invalid")
                val digest = MessageDigest.getInstance("SHA-256")
                digestIndex(digest, index, count)
                var position = 0L
                val checked = object : ControlTransferSpool {
                    override fun read(start: Long, length: Int): ByteArray {
                        if (start != position) throw IOException("Retained result read order changed")
                        return resource.read(offset + start, length).also { digest.update(it); position += it.size }
                    }
                    override fun append(bytes: ByteArray): Unit = error("Retained results are immutable")
                    override fun sha256(): String = error("Not a public transfer")
                    override fun erase(): Unit = error("Result reader does not own its storage")
                }
                val text = AndroidNativeString.decode(checked, count, false, bytes)
                val expected = record.copyOfRange(12, INDEX_BYTES)
                val actual = digest.digest()
                try {
                    if (position != bytes || !MessageDigest.isEqual(expected, actual))
                        throw IOException("Retained result verification failed")
                } finally { expected.fill(0); actual.fill(0) }
                return ControlValue.Text(text)
            } finally { record.fill(0) }
        }
        override fun toString() = "AndroidRetainedControlValues(<redacted>)"
    }

    private class Writer(private val spool: ControlTransferSpool) : AutoCloseable {
        private val buffer = ByteArray(CHUNK)
        private var used = 0
        var count = 0L
            private set
        val position: Long get() = count + used
        fun byte(value: Int) {
            buffer[used++] = value.toByte()
            if (used == buffer.size) flush()
        }
        fun int(value: Int) { for (shift in 24 downTo 0 step 8) byte(value ushr shift) }
        fun long(value: Long) { for (shift in 56 downTo 0 step 8) byte((value ushr shift).toInt()) }
        fun bytes(values: ByteArray) { for (value in values) byte(value.toInt()) }
        fun text(value: String) { for (unit in value) { byte(unit.code ushr 8); byte(unit.code) } }
        fun flush() {
            if (used == 0) return
            val bytes = buffer.copyOf(used)
            try { spool.append(bytes); count += used; used = 0 }
            finally { bytes.fill(0) }
        }
        override fun close() { buffer.fill(0) }
    }

    companion object {
        private const val CHUNK = 65536
        private const val INDEX_BYTES = 8 + 4 + 32
        private const val DISK_THRESHOLD = 32768L

        private fun large(values: List<ControlValue>): Boolean {
            var characters = 0L
            for (value in values) {
                characters += (value as? ControlValue.Text)?.value?.length ?: return false
                if (characters >= DISK_THRESHOLD) return true
            }
            return false
        }

        private fun write(values: List<ControlValue>, spool: ControlTransferSpool): Values {
            val count = values.size
            var offset = count.toLong() * INDEX_BYTES
            Writer(spool).use { writer ->
                val digest = MessageDigest.getInstance("SHA-256")
                // The immutable generated input is revisited, never copied into
                // an in-memory index or retained after this function returns.
                for (index in 0 until count) {
                    val text = (values[index] as? ControlValue.Text)?.value ?: throw IOException("Retained result type changed")
                    writer.long(offset); writer.int(text.length)
                    digestIndex(digest, index, text.length)
                    for (unit in text) { digest.update((unit.code ushr 8).toByte()); digest.update(unit.code.toByte()) }
                    val hash = digest.digest()
                    try { writer.bytes(hash) } finally { hash.fill(0) }
                    val bytes = text.length.toLong() * 2
                    if (offset > Long.MAX_VALUE - bytes) throw OutOfMemoryError("Retained result is too large")
                    offset += bytes
                }
                writer.flush()
                for (index in 0 until count) {
                    val text = (values[index] as? ControlValue.Text)?.value ?: throw IOException("Retained result type changed")
                    val record = spool.read(index.toLong() * INDEX_BYTES, INDEX_BYTES)
                    try {
                        if (record.size != INDEX_BYTES || longAt(record, 0) != writer.position || intAt(record, 8) != text.length)
                            throw IOException("Retained result changed during capture")
                        digestIndex(digest, index, text.length)
                        for (unit in text) { digest.update((unit.code ushr 8).toByte()); digest.update(unit.code.toByte()) }
                        val expected = record.copyOfRange(12, INDEX_BYTES)
                        val actual = digest.digest()
                        try {
                            if (!MessageDigest.isEqual(expected, actual)) throw IOException("Retained result changed during capture")
                        } finally { expected.fill(0); actual.fill(0) }
                        writer.text(text)
                    } finally { record.fill(0) }
                }
                writer.flush()
                if (writer.count != offset || values.size != count) throw IOException("Retained result changed during capture")
            }
            return Values(Resource(spool, offset), count)
        }

        private fun digestIndex(digest: MessageDigest, index: Int, count: Int) {
            for (value in intArrayOf(index, count)) for (shift in 24 downTo 0 step 8) digest.update((value ushr shift).toByte())
        }
        private fun intAt(bytes: ByteArray, start: Int): Int {
            var value = 0
            for (index in start until start + 4) value = (value shl 8) or (bytes[index].toInt() and 255)
            return value
        }
        private fun longAt(bytes: ByteArray, start: Int): Long {
            var value = 0L
            for (index in start until start + 8) value = (value shl 8) or (bytes[index].toLong() and 255)
            return value
        }
    }
}
