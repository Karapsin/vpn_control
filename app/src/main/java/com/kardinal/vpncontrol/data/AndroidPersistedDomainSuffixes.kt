package com.kardinal.vpncontrol.data

import java.util.RandomAccess
import com.kardinal.vpncontrol.model.ControlValue

/**
 * Immutable projection of the existing newline preference. Keep ranges into its
 * string instead of retaining another full copy of every domain beside DataStore.
 * Normalization still needs ranges and a temporary distinct set; this is not constant-memory parsing.
 */
internal class AndroidPersistedDomainSuffixes private constructor(
    private val source: String,
    private val rangeChunks: Array<LongArray>,
    private val count: Int,
) : AbstractList<String>(), RandomAccess, RoutingRulesRetainedStrings {
    override val size: Int get() = count

    override fun get(index: Int): String {
        if (index !in 0 until count) throw IndexOutOfBoundsException("index: $index, size: $count")
        val range = rangeChunks[index / RANGE_CHUNK][index % RANGE_CHUNK]
        return source.substring((range ushr 32).toInt(), range.toInt()).lowercase()
    }

    // The immutable source stores characters and ranges, not retained token
    // strings. Copying every substring into an import reuse pool increases peak
    // memory without sharing any object that this snapshot already owns.
    override fun findRetainedString(value: String): String? = null

    /** Retained operations share this immutable snapshot without recreating all tokens. */
    fun controlValues(): List<ControlValue> = object : AbstractList<ControlValue>(), RandomAccess {
        override val size: Int get() = this@AndroidPersistedDomainSuffixes.size
        override fun get(index: Int): ControlValue = ControlValue.Text(this@AndroidPersistedDomainSuffixes[index])
    }

    /** Hash-table keys retain ranges, not normalized copies of the entire preference. */
    private class Key(private val source: String, val range: Long, private val hash: Int) : Comparable<Key> {
        private fun value(): String = source.substring((range ushr 32).toInt(), range.toInt()).lowercase()
        override fun hashCode(): Int = hash
        override fun equals(other: Any?): Boolean = other is Key && hash == other.hash && compareTo(other) == 0
        // Comparable keys keep deliberate string-hash collisions bounded by the
        // platform hash map's tree ordering, with the same normalized equality.
        override fun compareTo(other: Key): Int = value().compareTo(other.value())
    }

    companion object {
        // Fixed chunks prevent a second large range array while preserving only
        // the ranges for unique retained suffixes.
        private const val RANGE_CHUNK = 1_024

        fun decode(raw: String?): List<String> {
            if (raw.isNullOrEmpty()) return emptyList()
            val seen = HashSet<Key>()
            val chunks = ArrayList<LongArray>()
            var count = 0
            var position = 0
            while (position < raw.length) {
                var start = position
                while (position < raw.length && raw[position] !in ",\n\r\t ") position++
                var end = position
                if (position < raw.length) position++
                // Match decodeList plus RoutingRules.parseDirectDomainSuffixes,
                // including legacy whitespace, wildcard prefixes and Unicode casing.
                while (start < end && raw[start].isWhitespace()) start++
                while (end > start && raw[end - 1].isWhitespace()) end--
                if (end - start >= 2 && raw[start] == '*' && raw[start + 1] == '.') start += 2
                while (start < end && raw[start] == '.') start++
                while (end > start && raw[end - 1] == '.') end--
                if (start == end) continue
                val normalized = raw.substring(start, end).lowercase()
                val range = (start.toLong() shl 32) or end.toLong()
                if (normalized.isBlank() || !seen.add(Key(raw, range, normalized.hashCode()))) continue
                if (count == Int.MAX_VALUE) throw OutOfMemoryError()
                if (count % RANGE_CHUNK == 0) chunks += LongArray(RANGE_CHUNK)
                chunks[count / RANGE_CHUNK][count % RANGE_CHUNK] = range
                count++
            }
            return if (count == 0) emptyList() else AndroidPersistedDomainSuffixes(raw, chunks.toTypedArray(), count)
        }
    }
}
