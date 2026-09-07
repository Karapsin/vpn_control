package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.control.ControlCharacterSource
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Optional reuse lookup for immutable lists that do not retain an ordinary token
 * array. Return only an already retained string, or null when reuse would create
 * a new copy. Parsing and normalization still validate every input token.
 */
interface RoutingRulesRetainedStrings {
    fun findRetainedString(value: String): String?
}

/** Domain parser: retain normalized rules, not the source document or a second JSON tree. */
internal class RoutingRulesCharacterImport(
    private val source: ControlCharacterSource,
    private val existing: RoutingRules? = null,
) {
    // Reference arrays avoid a second per-token hash table next to the distinct set.
    // Build only fields encountered by the document; never sort the caller's lists.
    private val existingDomains by lazy { existing?.directDomainSuffixes?.toTypedArray()?.also { it.sort() } }
    private val existingPackages by lazy { existing?.proxyPackages?.toTypedArray()?.also { it.sort() } }
    private fun reuse(value: String, domains: Boolean): String {
        val values = if (domains) existing?.directDomainSuffixes else existing?.proxyPackages
        if (values is RoutingRulesRetainedStrings) {
            // A range-backed immutable view has no per-token objects to share.
            // Let it avoid materializing an entire second string pool merely to
            // return an equal copy of the string already parsed here.
            return values.findRetainedString(value)?.takeIf { it == value } ?: value
        }
        val pool = (if (domains) existingDomains else existingPackages) ?: return value
        val index = pool.binarySearch(value)
        return if (index >= 0) pool[index] else value
    }
    private data class Parsed<T>(val value: T, val valid: Boolean = true)
    private class Fields {
        var recognized = false
        var ignore = Parsed(false)
        var quic = Parsed(false)
        var packages = Parsed(emptyList<String>())
        var domains = Parsed(emptyList<String>())
    }
    private var next = -2
    private fun peek(): Int {
        if (next == -2) next = source.read().also { require(it in -1..65535) }
        return next
    }
    private fun take() = peek().also { next = -2 }
    private fun space() { while (peek() in listOf(32, 9, 10, 13)) take() }
    private fun expect(char: Char) { require(take() == char.code) { "Invalid routing JSON" } }
    private fun invalid(): Nothing = throw IllegalArgumentException("Invalid routing JSON")

    fun read(): RoutingRules {
        var type = Parsed<String?>(null)
        var wrapped: Fields? = null
        var hasWrapper = false
        val root = Fields()
        objectFields { key ->
            when (key) {
                "type" -> type = primitive()
                "rules" -> {
                    hasWrapper = true
                    wrapped = if (peek() == '{'.code) Fields().also { fields -> objectFields { readField(fields, it) } }
                        else { skipValue(); null }
                }
                else -> readField(root, key)
            }
        }
        space(); require(peek() == -1) { "Invalid routing JSON" }
        val fields = if (hasWrapper) requireNotNull(wrapped) else root
        require(type.valid && (type.value == RoutingRulesTransfer.FORMAT_TYPE || fields.recognized)) {
            "Routing rules JSON format is not recognized"
        }
        require(fields.ignore.valid && fields.quic.valid && fields.packages.valid && fields.domains.valid)
        return RoutingRules(ignoreRules = fields.ignore.value, blockQuicUdp443 = fields.quic.value,
            proxyPackages = fields.packages.value, directDomainSuffixes = fields.domains.value,
            bypassPackages = emptyList(), ruleSets = emptyList())
    }

    private fun readField(fields: Fields, key: String) {
        when (key) {
            "ignore_rules", "block_quic_udp_443" -> {
                fields.recognized = true
                val value = primitive().let { Parsed(it.value == "true", it.valid) }
                if (key == "ignore_rules") fields.ignore = value else fields.quic = value
            }
            "proxy_packages", "direct_domain_suffixes" -> {
                fields.recognized = true
                val values = stringArray(domains = key == "direct_domain_suffixes")
                if (key == "proxy_packages") fields.packages = values else fields.domains = values
            }
            "national_domain_suffixes", "rule_sets" -> { fields.recognized = true; skipValue() }
            else -> skipValue()
        }
    }

    /** Duplicate domain keys deliberately keep the last value, matching the legacy tree decoder. */
    private fun objectFields(field: (String) -> Unit) {
        space(); expect('{'); space()
        if (peek() == '}'.code) { take(); return }
        while (true) {
            val key = string()
            space(); expect(':'); space()
            field(key)
            space()
            when (take()) {
                '}'.code -> return
                ','.code -> space()
                else -> invalid()
            }
        }
    }

    private fun primitive(): Parsed<String?> {
        space()
        if (peek() == '"'.code) return Parsed(string())
        if (peek() == '{'.code || peek() == '['.code) { skipValue(); return Parsed(null, false) }
        return Parsed(scalar().contentOrNull)
    }

    private fun stringArray(domains: Boolean): Parsed<List<String>> {
        space()
        if (peek() != '['.code) { skipValue(); return Parsed(emptyList(), false) }
        take(); space()
        val values = linkedSetOf<String>()
        var valid = true
        fun add(raw: String) {
            val value = raw.trim()
            if (value.isNotBlank()) {
                if (domains) {
                    val normalized = value.removePrefix("*.").trimStart('.').trimEnd('.').lowercase()
                    if (normalized.isNotBlank()) values.add(reuse(normalized, domains = true))
                } else values.add(reuse(value, domains = false))
            }
        }
        if (peek() == ']'.code) { take(); return Parsed(emptyList()) }
        while (true) {
            space()
            if (domains && peek() == '"'.code) {
                // A single array string may itself contain millions of comma-separated domains.
                val token = StringBuilder()
                fun finish() { add(token.toString()); token.clear() }
                string { char -> if (char in ",\n\r\t ") finish() else token.append(char) }
                finish()
            } else {
                val item = primitive()
                valid = valid && item.valid
                item.value?.let(::add)
            }
            space()
            when (take()) {
                ']'.code -> return Parsed(if (domains) values.toList() else values.sorted(), valid)
                ','.code -> Unit
                else -> invalid()
            }
        }
    }

    private fun scalar(): JsonPrimitive {
        val token = StringBuilder()
        while (peek() != -1 && peek() !in listOf(32, 9, 10, 13, ','.code, ']'.code, '}'.code)) {
            token.append(take().toChar())
        }
        require(token.isNotEmpty()) { "Invalid routing JSON" }
        return try { CompactJson.parseToJsonElement(token.toString()) as? JsonPrimitive ?: invalid() }
        catch (_: IllegalArgumentException) { invalid() }
    }

    private fun string(): String = StringBuilder().also { result -> string { result.append(it) } }.toString()
    private fun string(append: (Char) -> Unit) {
        expect('"')
        while (true) {
            val unit = take()
            when (unit) {
                -1 -> invalid()
                '"'.code -> return
                '\\'.code -> append(when (val escape = take()) {
                    '"'.code, '\\'.code, '/'.code -> escape.toChar()
                    'b'.code -> '\b'
                    'f'.code -> '\u000c'
                    'n'.code -> '\n'
                    'r'.code -> '\r'
                    't'.code -> '\t'
                    'u'.code -> {
                        var code = 0
                        repeat(4) {
                            val digit = when (val character = take()) {
                                in '0'.code..'9'.code -> character - '0'.code
                                in 'a'.code..'f'.code -> character - 'a'.code + 10
                                in 'A'.code..'F'.code -> character - 'A'.code + 10
                                else -> invalid()
                            }
                            code = code * 16 + digit
                        }
                        code.toChar()
                    }
                    else -> invalid()
                })
                else -> append(unit.toChar()) // Preserve the legacy parser's literal UTF-16 behavior.
            }
        }
    }

    /** Explicit stack validates ignored JSON without recursive calls or a control-envelope depth cap. */
    private fun skipValue() {
        data class Frame(val objectValue: Boolean, var state: Int = 0)
        val stack = mutableListOf<Frame>()
        fun begin() {
            space()
            when (peek()) {
                '{'.code -> { take(); stack.add(Frame(true)) }
                '['.code -> { take(); stack.add(Frame(false)) }
                '"'.code -> string { }
                else -> scalar()
            }
        }
        begin()
        while (stack.isNotEmpty()) {
            val frame = stack.last()
            space()
            val close = if (frame.objectValue) '}' else ']'
            if (frame.state == 2) {
                when (take()) {
                    close.code -> stack.removeAt(stack.lastIndex)
                    ','.code -> frame.state = 1
                    else -> invalid()
                }
            } else if (frame.state == 0 && peek() == close.code) {
                take(); stack.removeAt(stack.lastIndex)
            } else {
                if (frame.objectValue) { string { }; space(); expect(':') }
                frame.state = 2
                begin()
            }
        }
    }
}
