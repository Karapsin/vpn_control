package com.kardinal.vpncontrol.data

import androidx.datastore.core.CorruptionException
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.byteArrayPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.mutablePreferencesOf
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.kardinal.vpncontrol.AndroidControlTransferSpool
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Bounded reader for AndroidX's stable preferences.proto wire format. AndroidX's
 * generated reader materializes a length-delimited value before constructing a
 * String; that transient full document allocation exceeds ART's 48 MiB growth
 * limit for the routing preference. This accepts the same map/value oneof while
 * streaming string payloads in bounded chunks. Byte-array preference values
 * retain their documented value-sized allocation.
 */
internal object AndroidPreferencesProtoReader {
    private const val BUFFER = 65_536
    private const val MAX_GROUP_DEPTH = 100

    fun read(input: InputStream, privateCache: java.nio.file.Path): Preferences = try {
        val reader = Wire(input)
        val values = mutablePreferencesOf()
        while (true) {
            val tag = reader.tag() ?: break
            if (tag.field != 1 || tag.wire != LENGTH) {
                reader.skip(tag)
                continue
            }
            val length = reader.length()
            val entry = LimitedInputStream(input, length.toLong())
            val parsed = readEntry(Wire(entry), privateCache)
            entry.requireFullyRead()
            if (parsed != null) values.put(parsed.first, parsed.second)
        }
        values.toPreferences()
    } catch (failure: WireFormatException) {
        throw CorruptionException("Invalid preferences protobuf", failure)
    }

    private fun readEntry(reader: Wire, privateCache: java.nio.file.Path): Pair<Preferences.Key<*>, Any>? {
        var name: String? = null
        var value: Any? = null
        while (true) {
            val tag = reader.tag() ?: break
            when (tag.field) {
                1 -> if (tag.wire == LENGTH) name = reader.string(reader.length(), privateCache, strictUtf8 = true) else reader.skip(tag)
                2 -> if (tag.wire == LENGTH) {
                    value = readValue(Wire(LimitedInputStream(reader.input, reader.length().toLong())), privateCache)
                } else reader.skip(tag)
                else -> reader.skip(tag)
            }
        }
        // protobuf map entries default an omitted string key to the empty string.
        // A preferences value has no usable default oneof: stock treats this as
        // corrupt rather than silently dropping a persisted map entry.
        val key = name.orEmpty()
        val actual = value ?: throw WireFormatException("Preferences value is missing")
        return keyFor(key, actual) to actual
    }

    private fun readValue(reader: Wire, privateCache: java.nio.file.Path): Any? {
        var result: Any? = null
        while (true) {
            val tag = reader.tag() ?: break
            result = when (tag.field) {
                1 -> if (tag.wire == VARINT) reader.varint() != 0L else { reader.skip(tag); result }
                2 -> if (tag.wire == FIXED32) java.lang.Float.intBitsToFloat(reader.fixed32()) else { reader.skip(tag); result }
                3 -> if (tag.wire == VARINT) reader.varint().toInt() else { reader.skip(tag); result }
                4 -> if (tag.wire == VARINT) reader.varint() else { reader.skip(tag); result }
                5 -> if (tag.wire == LENGTH) reader.string(reader.length(), privateCache) else { reader.skip(tag); result }
                6 -> if (tag.wire == LENGTH) {
                    val next = readStringSet(Wire(LimitedInputStream(reader.input, reader.length().toLong())), privateCache)
                    if (result is Set<*>) LinkedHashSet<String>((result as Set<String>) + next) else next
                } else { reader.skip(tag); result }
                7 -> if (tag.wire == FIXED64) java.lang.Double.longBitsToDouble(reader.fixed64()) else { reader.skip(tag); result }
                8 -> if (tag.wire == LENGTH) reader.bytes(reader.length()) else { reader.skip(tag); result }
                else -> { reader.skip(tag); result }
            }
        }
        return result
    }

    private fun readStringSet(reader: Wire, privateCache: java.nio.file.Path): Set<String> {
        val result = LinkedHashSet<String>()
        while (true) {
            val tag = reader.tag() ?: break
            if (tag.field == 1 && tag.wire == LENGTH) {
                result += reader.string(reader.length(), privateCache)
            } else reader.skip(tag)
        }
        return result
    }

    private fun keyFor(name: String, value: Any): Preferences.Key<*> = when (value) {
        is Boolean -> booleanPreferencesKey(name)
        is Float -> floatPreferencesKey(name)
        is Int -> intPreferencesKey(name)
        is Long -> longPreferencesKey(name)
        is String -> stringPreferencesKey(name)
        is Set<*> -> stringSetPreferencesKey(name)
        is Double -> doublePreferencesKey(name)
        is ByteArray -> byteArrayPreferencesKey(name)
        else -> throw IOException("Unsupported preferences value")
    }

    @Suppress("UNCHECKED_CAST")
    private fun androidx.datastore.preferences.core.MutablePreferences.put(key: Preferences.Key<*>, value: Any) {
        this[key as Preferences.Key<Any>] = value
    }

    private class WireFormatException(message: String) : IOException(message)

    private data class Tag(val field: Int, val wire: Int)

    private class Wire(val input: InputStream) {
        fun tag(): Tag? {
            val first = input.read()
            if (first < 0) return null
            val value = varint(first).toInt()
            val field = value ushr 3
            if (field == 0) throw WireFormatException("Invalid preferences field")
            return Tag(field, value and 7)
        }
        fun varint(): Long {
            val first = input.read()
            if (first < 0) throw WireFormatException("Truncated preferences")
            return varint(first)
        }
        private fun varint(first: Int): Long {
            var value = (first and 127).toLong()
            var shift = 7
            var next = first
            while (next and 128 != 0) {
                if (shift >= 64) throw WireFormatException("Invalid preferences varint")
                next = input.read()
                if (next < 0) throw WireFormatException("Truncated preferences")
                value = value or ((next and 127).toLong() shl shift)
                shift += 7
            }
            return value
        }
        fun length(): Int {
            val value = varint().toInt()
            if (value < 0) throw WireFormatException("Invalid preferences length")
            return value
        }
        private fun decodeStrictUtf8(bytes: ByteArray): String = try {
            strictUtf8Decoder().decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: CharacterCodingException) {
            throw WireFormatException("Invalid UTF-8 preferences key")
        }

        private fun strictUtf8Decoder() = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)

        fun fixed32(): Int = bytes(4).let { bytes -> try {
            (bytes[0].toInt() and 255) or ((bytes[1].toInt() and 255) shl 8) or
                ((bytes[2].toInt() and 255) shl 16) or ((bytes[3].toInt() and 255) shl 24)
        } finally { bytes.fill(0) } }
        fun fixed64(): Long = bytes(8).let { bytes -> try {
            var value = 0L; for (index in 0 until 8) value = value or ((bytes[index].toLong() and 255) shl (index * 8)); value
        } finally { bytes.fill(0) } }
        fun bytes(length: Int): ByteArray {
            val result = ByteArray(length)
            try { readFully(result); return result } catch (failure: Throwable) { result.fill(0); throw failure }
        }
        fun string(length: Int, privateCache: java.nio.file.Path, strictUtf8: Boolean = false): String {
            if (length <= BUFFER) return bytes(length).let { bytes -> try {
                if (strictUtf8) decodeStrictUtf8(bytes) else String(bytes, StandardCharsets.UTF_8)
            } finally { bytes.fill(0) } }
            val limited = LimitedInputStream(input, length.toLong())
            val spool = AndroidControlTransferSpool.create(privateCache)
            var failure: Throwable? = null
            try {
                val chars = CharArray(BUFFER / 2)
                val encoded = ByteArray(BUFFER)
                var count = 0L
                try {
                    val source = if (strictUtf8) {
                        InputStreamReader(limited, strictUtf8Decoder())
                    } else {
                        InputStreamReader(limited, StandardCharsets.UTF_8)
                    }
                    source.use {
                        while (true) {
                            val read = source.read(chars)
                            if (read < 0) break
                            var used = 0
                            for (index in 0 until read) {
                                val unit = chars[index]
                                encoded[used++] = (unit.code ushr 8).toByte()
                                encoded[used++] = unit.code.toByte()
                            }
                            // ControlTransferSpool accepts complete arrays. Full chunks reuse
                            // the bounded buffer; only the final partial chunk is copied.
                            val chunk = if (used == encoded.size) encoded else ByteArray(used).also {
                                encoded.copyInto(it, endIndex = used)
                            }
                            spool.append(chunk)
                            if (chunk !== encoded) chunk.fill(0)
                            encoded.fill(0, 0, used)
                            chars.fill('\u0000', 0, read)
                            count += read
                        }
                    }
                } finally {
                    chars.fill('\u0000')
                    encoded.fill(0)
                }
                limited.requireFullyRead()
                if (count > Int.MAX_VALUE) throw OutOfMemoryError()
                return AndroidNativeString.decode(spool, count.toInt(), false, count * 2)
            } catch (caught: CharacterCodingException) {
                val malformed = WireFormatException("Invalid UTF-8 preferences key")
                failure = malformed
                throw malformed
            } catch (caught: Throwable) {
                failure = caught
                throw caught
            } finally {
                if (failure == null) spool.erase() else runCatching { spool.erase() }
            }
        }
        fun skip(tag: Tag, depth: Int = 0) {
            when (tag.wire) {
                VARINT -> varint()
                FIXED64 -> discard(8)
                LENGTH -> discard(length())
                FIXED32 -> discard(4)
                START_GROUP -> {
                    if (depth >= MAX_GROUP_DEPTH) throw WireFormatException("Preferences group nesting is too deep")
                    while (true) {
                        val nested = tag() ?: throw WireFormatException("Truncated preferences group")
                        if (nested.wire == END_GROUP) {
                            if (nested.field != tag.field) throw WireFormatException("Mismatched preferences group end")
                            break
                        }
                        skip(nested, depth + 1)
                    }
                }
                END_GROUP -> throw WireFormatException("Unexpected preferences group end")
                else -> throw WireFormatException("Unsupported preferences wire type")
            }
        }
        private fun discard(length: Int) { val bytes = ByteArray(minOf(BUFFER, length)); try { var left = length; while (left > 0) { val count = minOf(left, bytes.size); readFully(bytes, 0, count); left -= count } } finally { bytes.fill(0) } }
        private fun readFully(bytes: ByteArray, start: Int = 0, count: Int = bytes.size) { var offset = start; val end = start + count; while (offset < end) { val read = input.read(bytes, offset, end - offset); if (read < 0) throw WireFormatException("Truncated preferences"); if (read == 0) continue; offset += read } }
    }

    private class LimitedInputStream(private val delegate: InputStream, private var remaining: Long) : InputStream() {
        override fun read(): Int { if (remaining == 0L) return -1; val value = delegate.read(); if (value < 0) throw WireFormatException("Truncated preferences"); remaining--; return value }
        override fun read(bytes: ByteArray, offset: Int, count: Int): Int { if (remaining == 0L) return -1; val read = delegate.read(bytes, offset, minOf(count.toLong(), remaining).toInt()); if (read < 0) throw WireFormatException("Truncated preferences"); if (read > 0) remaining -= read; return read }
        override fun close() = Unit
        fun requireFullyRead() { if (remaining != 0L) throw WireFormatException("Invalid preferences length") }
    }

    private const val VARINT = 0
    private const val FIXED64 = 1
    private const val LENGTH = 2
    private const val START_GROUP = 3
    private const val END_GROUP = 4
    private const val FIXED32 = 5
}
