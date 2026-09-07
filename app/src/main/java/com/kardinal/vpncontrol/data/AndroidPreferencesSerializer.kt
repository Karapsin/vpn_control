package com.kardinal.vpncontrol.data

import androidx.datastore.core.Serializer
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferencesSerializer
import java.io.InputStream
import java.io.OutputStream

/** Same AndroidX preference protobuf, with bounded output buffers and verified immutable reuse. */
internal class AndroidPreferencesSerializer(private val privateCache: java.nio.file.Path) : Serializer<Preferences> {
    private data class Cached(val value: java.lang.ref.WeakReference<Preferences>, val count: Long, val digest: ByteArray)
    @Volatile private var cached: Cached? = null
    override val defaultValue: Preferences get() = PreferencesSerializer.defaultValue

    override suspend fun readFrom(input: InputStream): Preferences {
        val candidate = cached
        val spool = com.kardinal.vpncontrol.AndroidControlTransferSpool.create(privateCache)
        try {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            var count = 0L
            val bytes = ByteArray(65536)
            try {
                while (true) {
                    val size = input.read(bytes)
                    if (size < 0) break
                    if (size == 0) continue
                    val chunk = bytes.copyOf(size)
                    try { spool.append(chunk); digest.update(chunk); count += size }
                    finally { chunk.fill(0) }
                }
            } finally { bytes.fill(0) }
            // Full-file cryptographic identity, including EOF, not a timestamp or optimistic cache.
            val hash = digest.digest()
            if (candidate != null && candidate.count == count && candidate.digest.contentEquals(hash))
                candidate.value.get()?.let { return it }
            var offset = 0L
            val replay = object : InputStream() {
                override fun read(): Int = if (offset == count) -1 else spool.read(offset++, 1).let { bytes -> try { bytes[0].toInt() and 255 } finally { bytes.fill(0) } }
                override fun read(target: ByteArray, start: Int, length: Int): Int {
                    if (length == 0) return 0
                    if (offset == count) return -1
                    val chunk = spool.read(offset, minOf(length.toLong(), count - offset, 65536L).toInt())
                    chunk.copyInto(target, start); offset += chunk.size
                    return chunk.size.also { chunk.fill(0) }
                }
            }
            val decoded = AndroidPreferencesProtoReader.read(replay, privateCache)
            // Cold process reads are also proven by complete bytes plus successful stock decode.
            // Return this same frozen instance so DataStore, not the cache, owns its lifetime.
            cached = Cached(java.lang.ref.WeakReference(decoded), count, hash)
            return decoded
        } finally { spool.erase() }
    }

    override suspend fun writeTo(t: Preferences, output: OutputStream) {
        val identity = AndroidPreferencesProtoWriter.write(t, output)
        // Zero-pair putAll only checks AndroidX's public frozen guard; it changes no values.
        val frozen = if (t is androidx.datastore.preferences.core.MutablePreferences) {
            try { t.putAll(); false } catch (_: IllegalStateException) { true }
        } else false
        // Never retain a mutable caller's collections. Lone UTF16 units
        // are replaced by protobuf; such values cannot be returned as decoded cache hits.
        fun safe(text: String): Boolean {
            var index = 0
            while (index < text.length) {
                val unit = text[index++]
                if (unit.isHighSurrogate()) {
                    if (index == text.length || !text[index++].isLowSurrogate()) return false
                } else if (unit.isLowSurrogate()) return false
            }
            return true
        }
        if (frozen && t.asMap().all { (key, value) -> safe(key.name) && when(value) {
                is String -> safe(value)
                is Set<*> -> value.all { safe(it as String) }
                else -> true
            } }) {
            cached = Cached(java.lang.ref.WeakReference(t), identity.count, identity.digest)
        } else cached = null
    }
}
