package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.RoutingRules

/** Edits retain immutable committed domains by index instead of copying every domain string. */
object DirectDomainDrafts {
    private class Indexed(
        val source: List<String>, val order: IntArray, val added: List<String> = emptyList(),
    ) : AbstractList<String>() {
        override val size get() = order.size
        override fun get(index: Int): String = order[index].let { if (it >= 0) source[it] else added[-it - 1] }
    }

    /** Caller-owned lists are copied; our immutable indexed edits can be shared by a rendered draft. */
    fun snapshot(value: List<String>): List<String> = if (value is Indexed) value else RoutingRules.parseDirectDomainSuffixes(value)

    private fun indexed(source: List<String>) = source as? Indexed ?: Indexed(source, IntArray(source.size) { it })

    fun remove(source: List<String>, index: Int): List<String> {
        require(index in source.indices)
        val previous = indexed(source)
        return Indexed(previous.source, IntArray(previous.size - 1) { previous.order[if (it < index) it else it + 1] }, previous.added)
    }

    fun add(source: List<String>, input: String): List<String> {
        val additions = RoutingRules.parseDirectDomainSuffixes(input).filterNot { it in source }
        if (additions.isEmpty()) return source
        val previous = indexed(source)
        val added = previous.added + additions
        return Indexed(previous.source, IntArray(previous.size + additions.size) {
            if (it < previous.size) previous.order[it] else -(previous.added.size + it - previous.size) - 1
        }, added)
    }

    /** Sort indices only. Range-backed persisted lists must not become a retained list of strings. */
    fun orderedIndices(source: List<String>): List<Int> = source.indices.sortedWith(
        compareByDescending<Int> { '.' !in source[it] }.thenBy { source[it] },
    )
}
