package com.kardinal.vpncontrol.data

import androidx.datastore.preferences.core.Preferences
import java.io.OutputStream
import java.security.MessageDigest

/** AndroidX preferences.proto bytes, with bounded UTF8 buffers instead of a full-message array. */
internal object AndroidPreferencesProtoWriter {
    data class Identity(val count: Long, val digest: ByteArray)

    fun write(preferences: Preferences, output: OutputStream): Identity {
        // Freeze mutable collection inputs before the first output callback. Strings
        // are immutable; retaining them does not duplicate the large document.
        val entries = preferences.asMap().map { (key, value) -> key.name to when (value) {
            is ByteArray -> value.copyOf()
            is Set<*> -> LinkedHashSet(value.map { it as String })
            else -> value
        } }
        val writer = Writer(output)
        return try {
            for ((key, value) in entries) writer.entry(key, value)
            writer.finish()
        } finally {
            writer.erase()
            entries.forEach { (_, value) -> if (value is ByteArray) value.fill(0) }
        }
    }

    private class Writer(private val output: OutputStream) {
        private val buffer = ByteArray(65536)
        private var used = 0
        private var count = 0L
        private val digest = MessageDigest.getInstance("SHA-256")

        fun entry(key: String, value: Any) {
            val size = checked(stringSize(key) + framedSize(valueSize(value)))
            byte(10) // PreferenceMap.preferences = 1 (length-delimited map entry)
            varint(size)
            string(1, key)
            byte(18) // map entry value = 2
            varint(valueSize(value))
            value(value)
        }

        private fun valueSize(value: Any): Long = when (value) {
            is Boolean -> 2
            is Float -> 5
            is Int -> 1 + varintSize(value.toLong())
            is Long -> 1 + varintSize(value)
            is String -> stringSize(value)
            is Set<*> -> framedSize(setSize(value))
            is Double -> 9
            is ByteArray -> framedSize(value.size.toLong())
            else -> error("Unsupported preference value type")
        }

        private fun value(value: Any) {
            // Value's oneof field numbers are defined by AndroidX preferences.proto.
            when (value) {
                is Boolean -> { byte(8); byte(if (value) 1 else 0) }
                is Float -> { byte(21); fixed(java.lang.Float.floatToRawIntBits(value).toLong(), 4) }
                is Int -> { byte(24); varint(value.toLong()) }
                is Long -> { byte(32); varint(value) }
                is String -> string(5, value)
                is Set<*> -> {
                    byte(50); varint(setSize(value))
                    value.forEach { string(1, it as String) }
                }
                is Double -> { byte(57); fixed(java.lang.Double.doubleToRawLongBits(value), 8) }
                is ByteArray -> { byte(66); varint(value.size.toLong()); raw(value) }
                else -> error("Unsupported preference value type")
            }
        }

        private fun setSize(values: Set<*>): Long {
            var size = 0L
            for (value in values) size = checked(size + stringSize(value as String))
            return size
        }
        private fun stringSize(text: String) = framedSize(utf8Size(text))
        private fun framedSize(size: Long) = checked(1 + varintSize(size) + size)
        private fun checked(size: Long): Long {
            // AndroidX's Java protobuf parser uses signed-int message lengths.
            // Exceeding its representation is a resource failure, not bad input.
            if (size > Int.MAX_VALUE) throw OutOfMemoryError()
            return size
        }

        private fun utf8Size(text: String): Long {
            var count = 0L
            var index = 0
            while (index < text.length) {
                val unit = text[index++]
                count += when {
                    unit.code < 128 -> 1
                    unit.code < 2048 -> 2
                    unit.isHighSurrogate() && index < text.length && text[index].isLowSurrogate() -> { index++; 4 }
                    unit.isSurrogate() -> 1 // String.getBytes(UTF8) replacement used by protobuf.
                    else -> 3
                }
            }
            return checked(count)
        }

        private fun string(field: Int, text: String) {
            byte((field shl 3) or 2)
            varint(utf8Size(text))
            var index = 0
            while (index < text.length) {
                val unit = text[index++]
                when {
                    unit.code < 128 -> byte(unit.code)
                    unit.code < 2048 -> { byte(0xc0 or (unit.code ushr 6)); byte(0x80 or (unit.code and 63)) }
                    unit.isHighSurrogate() && index < text.length && text[index].isLowSurrogate() -> {
                        val point = 0x10000 + ((unit.code - 0xd800) shl 10) + text[index++].code - 0xdc00
                        byte(0xf0 or (point ushr 18)); byte(0x80 or ((point ushr 12) and 63))
                        byte(0x80 or ((point ushr 6) and 63)); byte(0x80 or (point and 63))
                    }
                    unit.isSurrogate() -> byte('?'.code)
                    else -> {
                        byte(0xe0 or (unit.code ushr 12)); byte(0x80 or ((unit.code ushr 6) and 63))
                        byte(0x80 or (unit.code and 63))
                    }
                }
            }
        }

        private fun varintSize(value: Long): Long {
            var remaining = value
            var bytes = 1L
            while (remaining and -128L != 0L) { bytes++; remaining = remaining ushr 7 }
            return bytes
        }
        private fun varint(value: Long) {
            var remaining = value
            while (remaining and -128L != 0L) {
                byte((remaining.toInt() and 127) or 128)
                remaining = remaining ushr 7
            }
            byte(remaining.toInt())
        }
        private fun fixed(value: Long, bytes: Int) {
            repeat(bytes) { byte((value ushr (it * 8)).toInt()) }
        }
        private fun byte(value: Int) {
            buffer[used++] = value.toByte()
            if (used == buffer.size) flush()
        }
        private fun raw(value: ByteArray) {
            var offset = 0
            while (offset < value.size) {
                val size = minOf(buffer.size - used, value.size - offset)
                value.copyInto(buffer, used, offset, offset + size)
                used += size; offset += size
                if (used == buffer.size) flush()
            }
        }
        private fun flush() {
            if (used == 0) return
            output.write(buffer, 0, used)
            digest.update(buffer, 0, used)
            count += used
            buffer.fill(0, 0, used)
            used = 0
        }
        fun finish(): Identity { flush(); return Identity(count, digest.digest()) }
        fun erase() { buffer.fill(0) }
    }
}
