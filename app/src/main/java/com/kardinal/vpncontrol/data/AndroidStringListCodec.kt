package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.control.ControlTransferSpool

/** Persisted newline-separated list representation; no change to on-disk syntax. */
internal object AndroidStringListCodec {
    fun encode(values: List<String>, spoolFactory: (() -> ControlTransferSpool)? = null): String =
        encode(values.size, values::get, {}, spoolFactory)

    /** Only a caller-owned copy may be consumed. Repository/model collections never enter here. */
    fun encodeOwned(values: Array<String?>, spoolFactory: (() -> ControlTransferSpool)? = null): String =
        encode(values.size, { requireNotNull(values[it]) }, { values[it] = null }, spoolFactory)

    private fun encode(count: Int, valueAt: (Int) -> String, release: (Int) -> Unit,
        spoolFactory: (() -> ControlTransferSpool)? = null): String {
        if (count == 0) return ""
        if (count == 1) return valueAt(0).also { release(0) }
        var size = count.toLong() - 1
        var ascii = true
        for (index in 0 until count) {
            val value = valueAt(index)
            size += value.length
            if (size > Int.MAX_VALUE) throw OutOfMemoryError()
            if (ascii && value.any { it.code > 127 }) ascii = false
        }
        if (spoolFactory != null) {
            val spool = spoolFactory()
            try {
                val buffer = ByteArray(65536)
                var used = 0
                var written = 0L
                fun flush() {
                    if (used == 0) return
                    val chunk = buffer.copyOf(used)
                    try { spool.append(chunk); written += used; used = 0 } finally { chunk.fill(0) }
                }
                fun append(unit: Char) {
                    if (!ascii) buffer[used++] = (unit.code ushr 8).toByte()
                    buffer[used++] = unit.code.toByte()
                    if (used == buffer.size) flush()
                }
                try {
                    for (index in 0 until count) {
                        if (index != 0) append('\n')
                        for (unit in valueAt(index)) append(unit)
                        release(index)
                    }
                    flush()
                } finally { buffer.fill(0) }
                // Keep the old immutable preference valid until the atomic commit.
                // NewString reads native input storage, so no second document-sized
                // Java input array overlaps the final preference allocation.
                return AndroidNativeString.decode(spool, size.toInt(), ascii, written)
            } finally { spool.erase() }
        }
        var offset = 0
        if (ascii) {
            val bytes = ByteArray(size.toInt())
            for (index in 0 until count) {
                val value = valueAt(index)
                if (index != 0) bytes[offset++] = 10
                for (char in value) bytes[offset++] = char.code.toByte()
                release(index)
            }
            return asciiString(bytes)
        }
        // Keep exact UTF16 units, including unpaired surrogates. Encoding them
        // through UTF8 would silently replace persisted content.
        val chars = CharArray(size.toInt())
        for (index in 0 until count) {
            val value = valueAt(index)
            if (index != 0) chars[offset++] = '\n'
            for (char in value) chars[offset++] = char
            release(index)
        }
        return chars.concatToString()
    }

    // API29's charset constructors create a UTF16 decoding array even for ASCII.
    // This public legacy constructor maps each validated byte to the same code
    // unit directly, with no charset conversion.
    @Suppress("DEPRECATION")
    private fun asciiString(bytes: ByteArray): String = java.lang.String(bytes, 0).toString()
}
