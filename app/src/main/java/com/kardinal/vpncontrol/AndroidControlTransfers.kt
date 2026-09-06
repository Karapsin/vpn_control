package com.kardinal.vpncontrol

import java.io.ByteArrayOutputStream
import java.util.UUID

/** Bounded process-memory transfers. No URI segment is ever resolved as a filesystem path. */
internal class AndroidControlTransfers(
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val capacity: Int = 32,
    private val ttlMillis: Long = 300_000,
    private val maxBytes: Int = 1_048_576,
) {
    private class PrivateBuffer : ByteArrayOutputStream() {
        fun erase() { buf.fill(0); reset() }
    }
    private class Entry(val uid: Int, val expires: Long) {
        var phase = "created"
        var input: PrivateBuffer? = null
        var result: ByteArray? = null
    }
    private val entries = mutableMapOf<String, Entry>()

    @Synchronized fun create(uid: Int): String {
        prune()
        check(entries.size < capacity) { "BUSY" }
        return UUID.randomUUID().toString().also { entries[it] = Entry(uid, clockMillis() + ttlMillis) }
    }

    @Synchronized fun phase(id: String, uid: Int): String = entry(id, uid).phase

    @Synchronized fun beginWrite(id: String, uid: Int) {
        val entry = entry(id, uid)
        check(entry.phase == "created") { "CONFLICT" }
        entry.phase = "writing"
        entry.input = PrivateBuffer()
    }

    @Synchronized fun append(id: String, uid: Int, offset: Long, bytes: ByteArray, size: Int): Int {
        val entry = entry(id, uid)
        check(entry.phase == "writing") { "CONFLICT" }
        val input = requireNotNull(entry.input)
        require(size in 0..bytes.size && offset == input.size().toLong() && size <= maxBytes - input.size()) {
            "INVALID_ARGUMENT"
        }
        input.write(bytes, 0, size)
        return size
    }

    @Synchronized fun finishWrite(id: String, uid: Int): ByteArray {
        val entry = entry(id, uid)
        check(entry.phase == "writing") { "CONFLICT" }
        val bytes = requireNotNull(entry.input).toByteArray()
        entry.input?.erase()
        entry.input = null
        entry.phase = "pending"
        return bytes
    }

    @Synchronized fun complete(id: String, uid: Int, result: ByteArray) {
        val entry = entry(id, uid)
        check(entry.phase == "pending") { "CONFLICT" }
        require(result.size <= maxBytes) { "INVALID_ARGUMENT" }
        entry.result = result.copyOf()
        entry.phase = "complete"
    }

    @Synchronized fun resultSize(id: String, uid: Int): Long = result(id, uid).size.toLong()

    @Synchronized fun read(id: String, uid: Int, offset: Long, size: Int, output: ByteArray): Int {
        val bytes = result(id, uid)
        require(offset >= 0 && size in 0..output.size) { "INVALID_ARGUMENT" }
        if (offset >= bytes.size) return 0
        val count = minOf(size, bytes.size - offset.toInt())
        bytes.copyInto(output, 0, offset.toInt(), offset.toInt() + count)
        return count
    }

    @Synchronized fun remove(id: String, uid: Int) {
        val entry = entry(id, uid)
        check(entry.phase != "pending") { "BUSY" }
        entry.input?.erase()
        entry.result?.fill(0)
        entries.remove(id)
    }

    private fun result(id: String, uid: Int): ByteArray =
        entry(id, uid).result ?: throw IllegalStateException("UNAVAILABLE")

    private fun entry(id: String, uid: Int): Entry {
        AndroidControlAccess.opaqueId(id)
        prune()
        val entry = entries[id] ?: throw IllegalStateException("NOT_FOUND")
        if (entry.uid != uid) throw SecurityException("PERMISSION_DENIED")
        return entry
    }

    private fun prune() {
        val now = clockMillis()
        entries.entries.removeAll {
            if (it.value.expires <= now) {
                it.value.input?.erase()
                it.value.result?.fill(0)
                true
            } else false
        }
    }
}
