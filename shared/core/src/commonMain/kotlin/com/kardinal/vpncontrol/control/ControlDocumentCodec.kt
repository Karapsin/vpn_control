package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.CONTROL_SCHEMA_VERSION
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put

/** UTF-16 code units (0..65535), or -1 at EOF. Platform adapters own IO and strict byte decoding. */
fun interface ControlCharacterSource {
    fun read(): Int
}

/** Extracted input is absent from request.arguments; only the caller's private sink retains it. */
data class ControlExternalInputRequest(val request: ControlRequest, val inputExtracted: Boolean)

/** Logical JSON documents. Only authenticated adapters may assemble these from bounded frames.
 * Domain parsing still materializes Strings; this is not a constant-memory parser.
 */
object ControlDocumentCodec {
    private const val MAX_DEPTH = 32
    private val json = Json { isLenient = false }

    fun encodeValues(values: Map<String, ControlValue>): String = checkedEncode(encodeObject(values))
    /** Same canonical characters as encodeValues, without materializing JSON strings. */
    fun writeValues(values: Map<String, ControlValue>, output: Appendable) {
        ValueWriter(output).objectValue(values, 1)
    }

    /** Exact canonical escaping, including lone UTF-16 surrogates; the caller owns source and sink. */
    fun writeQuotedText(source: ControlCharacterSource, output: Appendable) {
        output.append('"')
        while (true) {
            val unit = source.read()
            if (unit == -1) break
            if (unit !in 0..65535) invalid()
            quotedCharacter(unit.toChar(), output)
        }
        output.append('"')
    }

    private fun quotedCharacter(char: Char, output: Appendable) {
        when (char) {
            '"' -> output.append("\\\"")
            '\\' -> output.append("\\\\")
            '\b' -> output.append("\\b")
            '\t' -> output.append("\\t")
            '\n' -> output.append("\\n")
            '\u000C' -> output.append("\\f")
            '\r' -> output.append("\\r")
            else -> if (char.code < 32) {
                output.append("\\u00")
                output.append("0123456789abcdef"[char.code ushr 4])
                output.append("0123456789abcdef"[char.code and 15])
            } else output.append(char)
        }
    }

    private class ValueWriter(private val output: Appendable) {
        fun objectValue(values: Map<String, ControlValue>, depth: Int,
            resultContent: ((Appendable) -> Unit)? = null, trailingContent: ((Appendable) -> Unit)? = null) {
            if (depth > MAX_DEPTH) invalid()
            output.append('{')
            values.entries.forEachIndexed { index, (key, value) ->
                if (index != 0) output.append(',')
                quoted(key); output.append(':')
                if (key == "data" && resultContent != null) {
                    objectValue((value as ControlValue.ObjectValue).values, depth + 1, trailingContent = resultContent)
                } else value(value, depth)
            }
            if (trailingContent != null) {
                if (values.isNotEmpty()) output.append(',')
                quoted("content"); output.append(':'); output.append('"')
                trailingContent(object : Appendable {
                    override fun append(value: Char): Appendable { quotedCharacter(value, output); return this }
                    override fun append(value: CharSequence?): Appendable = append(value, 0, value?.length ?: 4)
                    override fun append(value: CharSequence?, startIndex: Int, endIndex: Int): Appendable {
                        val text = value ?: "null"
                        require(startIndex >= 0 && endIndex >= startIndex && endIndex <= text.length)
                        for (index in startIndex until endIndex) quotedCharacter(text[index], output)
                        return this
                    }
                })
                output.append('"')
            }
            output.append('}')
        }
        private fun value(value: ControlValue, depth: Int) {
            when (value) {
                ControlValue.Null -> output.append("null")
                is ControlValue.Text -> quoted(value.value)
                is ControlValue.BooleanValue -> output.append(value.value.toString())
                is ControlValue.IntegerValue -> output.append(value.value.toString())
                is ControlValue.DecimalValue -> output.append(JsonPrimitive(value.value).toString())
                is ControlValue.ObjectValue -> objectValue(value.values, depth + 1)
                is ControlValue.ArrayValue -> {
                    if (depth >= MAX_DEPTH) invalid()
                    output.append('[')
                    value.values.forEachIndexed { index, item ->
                        if (index != 0) output.append(',')
                        value(item, depth + 1)
                    }
                    output.append(']')
                }
            }
        }
        private fun quoted(text: String) {
            output.append('"')
            for (char in text) quotedCharacter(char, output)
            output.append('"')
        }
    }
    fun decodeValues(frame: String): Map<String, ControlValue> = safeDecode { decodeObject(parse(frame)) }

    fun encodeRequest(request: ControlRequest): String = checkedEncode(buildJsonObject {
        put("schemaVersion", request.schemaVersion)
        put("requestId", request.requestId)
        put("controllerId", request.controllerId?.let(::JsonPrimitive) ?: JsonNull)
        put("ifRevision", request.ifRevision?.let(::JsonPrimitive) ?: JsonNull)
        put("interactive", request.interactive)
        put("asynchronous", request.asynchronous)
        put("command", buildJsonObject {
            put("operation", request.command.operation.wireName)
            put("arguments", encodeObject(request.command.arguments))
        })
    })

    fun decodeRequest(frame: String): ControlRequest = safeDecode { decodeRequestObject(parse(frame)) }

    /** Avoids materializing the outer document. Domain string values are still materialized. */
    fun decodeRequest(source: ControlCharacterSource): ControlRequest = safeDecode {
        decodeRequestObject(CharacterParser(source).document())
    }

    /**
     * Diverts only command.arguments.input when it is a string. The sink may receive a
     * prefix before later validation fails, so callers must discard failed private spools.
     */
    fun decodeRequestWithExternalInput(source: ControlCharacterSource, inputSink: Appendable): ControlExternalInputRequest = safeDecode {
        val parser = CharacterParser(source, inputSink)
        ControlExternalInputRequest(decodeRequestObject(parser.document()), parser.inputExtracted)
    }

    private fun decodeRequestObject(root: JsonObject): ControlRequest {
        checkVersion(root)
        root.only("schemaVersion", "requestId", "controllerId", "ifRevision", "interactive", "asynchronous", "command")
        val command = root["command"] as? JsonObject ?: invalid()
        command.only("operation", "arguments")
        return ControlRequest(
            requestId = root.text("requestId"),
            controllerId = root.optionalText("controllerId"),
            ifRevision = root.optionalLong("ifRevision"),
            interactive = root.boolean("interactive"),
            asynchronous = root.boolean("asynchronous"),
            command = ControlCommand(
                ControlOperationId.entries.firstOrNull { it.wireName == command.text("operation") } ?: invalid(),
                decodeObject(command["arguments"]),
            ),
        )
    }

    private class CharacterParser(private val source: ControlCharacterSource, private val inputSink: Appendable? = null) {
        var inputExtracted = false
            private set
        private var next = -2
        private fun peek(): Int {
            if (next == -2) next = source.read().also { if (it !in -1..65535) invalid() }
            return next
        }
        private fun take(): Int = peek().also { next = -2 }
        private fun whitespace(char: Int) = char == 32 || char == 9 || char == 10 || char == 13
        private fun space() { while (whitespace(peek())) take() }
        private fun expect(char: Char) { if (take() != char.code) invalid() }
        fun document(): JsonObject {
            val result = value(0) as? JsonObject ?: invalid()
            space()
            if (peek() != -1) invalid()
            return result
        }
        private fun value(depth: Int, location: Int = if (depth == 0) 0 else -1): JsonElement {
            space()
            return when (peek()) {
                '{'.code -> {
                    if (depth >= MAX_DEPTH) invalid()
                    take(); space()
                    val fields = linkedMapOf<String, JsonElement>()
                    val seen = mutableSetOf<String>()
                    if (peek() == '}'.code) { take(); return JsonObject(fields) }
                    while (true) {
                        space()
                        if (peek() != '"'.code) invalid()
                        val key = string()
                        if (!seen.add(key)) invalid()
                        space(); expect(':')
                        space()
                        if (inputSink != null && location == 2 && key == "input" && peek() == '"'.code) {
                            string { inputSink.append(it) }
                            inputExtracted = true
                        } else {
                            val childLocation = when {
                                location == 0 && key == "command" -> 1
                                location == 1 && key == "arguments" -> 2
                                else -> -1
                            }
                            fields[key] = value(depth + 1, childLocation)
                        }
                        space()
                        when (take()) {
                            '}'.code -> return JsonObject(fields)
                            ','.code -> Unit
                            else -> invalid()
                        }
                    }
                    @Suppress("UNREACHABLE_CODE") JsonNull
                }
                '['.code -> {
                    if (depth >= MAX_DEPTH) invalid()
                    take(); space()
                    val elements = mutableListOf<JsonElement>()
                    if (peek() == ']'.code) { take(); return JsonArray(elements) }
                    while (true) {
                        elements += value(depth + 1)
                        space()
                        when (take()) {
                            ']'.code -> return JsonArray(elements)
                            ','.code -> Unit
                            else -> invalid()
                        }
                    }
                    @Suppress("UNREACHABLE_CODE") JsonNull
                }
                '"'.code -> JsonPrimitive(string())
                else -> {
                    val token = StringBuilder()
                    while (peek() != -1 && !whitespace(peek()) && peek() != ','.code && peek() != ']'.code && peek() != '}'.code) {
                        token.append(take().toChar())
                    }
                    if (token.isEmpty()) invalid()
                    json.parseToJsonElement(token.toString()).also { if (it !is JsonPrimitive) invalid() }
                }
            }
        }
        private fun string(): String {
            val result = CompactCharacters()
            string(result::append)
            return result.finish()
        }
        private fun string(append: (Char) -> Unit) {
            expect('"')
            while (true) {
                when (val char = take()) {
                    -1 -> invalid()
                    '"'.code -> return
                    '\\'.code -> when (take()) {
                        '"'.code -> append('"')
                        '\\'.code -> append('\\')
                        '/'.code -> append('/')
                        'b'.code -> append('\b')
                        'f'.code -> append('\u000c')
                        'n'.code -> append('\n')
                        'r'.code -> append('\r')
                        't'.code -> append('\t')
                        'u'.code -> {
                            var code = 0
                            repeat(4) {
                                val unit = take()
                                val digit = when (unit) {
                                    in '0'.code..'9'.code -> unit - '0'.code
                                    in 'a'.code..'f'.code -> unit - 'a'.code + 10
                                    in 'A'.code..'F'.code -> unit - 'A'.code + 10
                                    else -> invalid()
                                }
                                code = code * 16 + digit
                            }
                            append(code.toChar())
                        }
                        else -> invalid()
                    }
                    else -> {
                        // Preserve the existing kotlinx JSON tree parser's handling of literal
                        // UTF-16 units inside strings (including unpaired surrogates/control units).
                        append(char.toChar())
                    }
                }
            }
        }
    }

    /** Bounded allocation growth; ASCII/Latin1 uses one byte per UTF16 unit.
     * High bytes are allocated only for chunks that need them, preserving even
     * unpaired surrogates exactly. No document-size policy is imposed here.
     */
    private class CompactCharacters {
        private class Chunk(var low: ByteArray = ByteArray(128), var high: ByteArray? = null, var size: Int = 0)
        private val chunks = mutableListOf<Chunk?>()
        private var current = Chunk()
        private var length = 0
        private var ascii = true

        fun append(char: Char) {
            if (length == Int.MAX_VALUE) throw OutOfMemoryError()
            if (char.code > 127) ascii = false
            if (current.size == current.low.size) {
                if (current.size == 8192) {
                    chunks.add(current)
                    current = Chunk()
                } else {
                    current.low = current.low.copyOf(current.low.size * 2)
                    current.high = current.high?.copyOf(current.low.size)
                }
            }
            val index = current.size++
            current.low[index] = char.code.toByte()
            if (char.code > 255 && current.high == null) current.high = ByteArray(current.low.size)
            current.high?.set(index, (char.code ushr 8).toByte())
            length++
        }

        fun finish(): String {
            chunks.add(current)
            current = Chunk(ByteArray(0))
            if (ascii) {
                val output = ByteArray(length)
                var offset = 0
                for (index in chunks.indices) {
                    val chunk = requireNotNull(chunks[index])
                    chunk.low.copyInto(output, offset, 0, chunk.size)
                    offset += chunk.size
                    chunks[index] = null
                }
                chunks.clear()
                return output.decodeToString()
            }
            val output = CharArray(length)
            var offset = 0
            for (index in chunks.indices) {
                val chunk = requireNotNull(chunks[index])
                for (position in 0 until chunk.size) {
                    val low = chunk.low[position].toInt() and 255
                    val high = chunk.high?.get(position)?.toInt()?.and(255) ?: 0
                    output[offset++] = (low or (high shl 8)).toChar()
                }
                // Let the collector reclaim input chunks before the final String copy.
                chunks[index] = null
            }
            chunks.clear()
            return output.concatToString()
        }
    }

    /** Exact encodeResult characters without constructing a second result tree or whole JSON string. */
    fun writeResult(result: ControlResult, output: Appendable) = writeValues(resultValues(result), output)

    /**
     * Streams external text as the final data.content field. No content String or JSON tree is
     * created. The caller must discard partial output if the content writer or sink fails.
     */
    fun writeResultWithContent(result: ControlResult, output: Appendable, content: (Appendable) -> Unit) {
        require("content" !in result.data)
        ValueWriter(output).objectValue(resultValues(result), 1, resultContent = content)
    }

    private fun resultValues(result: ControlResult) = linkedMapOf(
        "schemaVersion" to ControlValue.IntegerValue(result.schemaVersion.toLong()),
        "controllerId" to (result.controllerId?.let(ControlValue::Text) ?: ControlValue.Null),
        "requestId" to ControlValue.Text(result.requestId),
        "ok" to ControlValue.BooleanValue(result.ok),
        "code" to ControlValue.Text(result.code.wireName),
        "message" to ControlValue.Text(result.message),
        "messageKey" to (result.messageKey?.let(ControlValue::Text) ?: ControlValue.Null),
        "messageArgs" to ControlValue.ArrayValue(result.messageArgs.map(ControlValue::Text)),
        "final" to ControlValue.BooleanValue(result.final),
        "operationId" to (result.operationId?.let(ControlValue::Text) ?: ControlValue.Null),
        "configurationRevision" to ControlValue.IntegerValue(result.configurationRevision),
        "restartRequired" to ControlValue.BooleanValue(result.restartRequired),
        "data" to ControlValue.ObjectValue(result.data),
        "warnings" to ControlValue.ArrayValue(result.warnings.map(ControlValue::Text)),
    )

    fun encodeResult(result: ControlResult): String = checkedEncode(buildJsonObject {
        put("schemaVersion", result.schemaVersion)
        put("controllerId", result.controllerId?.let(::JsonPrimitive) ?: JsonNull)
        put("requestId", result.requestId)
        put("ok", result.ok)
        put("code", result.code.wireName)
        put("message", result.message)
        put("messageKey", result.messageKey?.let(::JsonPrimitive) ?: JsonNull)
        put("messageArgs", JsonArray(result.messageArgs.map(::JsonPrimitive)))
        put("final", result.final)
        put("operationId", result.operationId?.let(::JsonPrimitive) ?: JsonNull)
        put("configurationRevision", result.configurationRevision)
        put("restartRequired", result.restartRequired)
        put("data", encodeObject(result.data))
        put("warnings", JsonArray(result.warnings.map(::JsonPrimitive)))
    })

    fun decodeResult(frame: String): ControlResult = safeDecode {
        val root = parse(frame)
        checkVersion(root)
        val code = ControlCode.entries.firstOrNull { it.wireName == root.text("code") } ?: invalid()
        val result = ControlResult(
            controllerId = root.optionalText("controllerId"),
            requestId = root.text("requestId"),
            code = code,
            configurationRevision = root.long("configurationRevision"),
            message = root.text("message"),
            messageKey = root.optionalText("messageKey"),
            messageArgs = root.strings("messageArgs"),
            final = root.boolean("final"),
            operationId = root.optionalText("operationId"),
            restartRequired = root.boolean("restartRequired"),
            data = decodeObject(root["data"]),
            warnings = root.strings("warnings"),
        )
        if (root.boolean("ok") != result.ok) invalid()
        result
    }

    private fun parse(frame: String): JsonObject {
        // Bound nesting before asking the JSON parser to recurse, independently of document size.
        checkNesting(frame)
        return json.parseToJsonElement(frame) as? JsonObject ?: invalid()
    }

    private fun checkNesting(frame: String) {
        var depth = 0
        var quoted = false
        var escaped = false
        var stringStart = 0
        val objectKeys = mutableListOf<MutableSet<String>?>()
        for ((index, char) in frame.withIndex()) {
            if (quoted) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == '"') {
                    quoted = false
                    var next = index + 1
                    while (next < frame.length && frame[next] in " \t\r\n") next++
                    if (next < frame.length && frame[next] == ':') {
                        val keys = objectKeys.lastOrNull() ?: invalid()
                        val key = (json.parseToJsonElement(frame.substring(stringStart, index + 1)) as JsonPrimitive).content
                        if (!keys.add(key)) invalid()
                    }
                }
            } else when (char) {
                '"' -> { quoted = true; stringStart = index }
                '{', '[' -> {
                    if (++depth > MAX_DEPTH) invalid()
                    objectKeys.add(if (char == '{') mutableSetOf() else null)
                }
                '}', ']' -> {
                    if (--depth < 0) invalid()
                    objectKeys.removeAt(objectKeys.lastIndex)
                }
            }
        }
        if (depth != 0 || quoted) invalid()
    }

    private fun checkedEncode(value: JsonObject): String {
        val frame = value.toString()
        checkNesting(frame)
        return frame
    }

    private fun checkVersion(root: JsonObject) {
        if (root.long("schemaVersion") != CONTROL_SCHEMA_VERSION.toLong()) {
            throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        }
    }

    private fun encodeObject(values: Map<String, ControlValue>): JsonObject =
        JsonObject(values.mapValues { encodeValue(it.value, 0) })

    private fun encodeValue(value: ControlValue, depth: Int): JsonElement {
        if (depth > MAX_DEPTH) invalid()
        return when (value) {
            ControlValue.Null -> JsonNull
            is ControlValue.Text -> JsonPrimitive(value.value)
            is ControlValue.BooleanValue -> JsonPrimitive(value.value)
            is ControlValue.IntegerValue -> JsonPrimitive(value.value)
            is ControlValue.DecimalValue -> JsonPrimitive(value.value)
            is ControlValue.ArrayValue -> JsonArray(value.values.map { encodeValue(it, depth + 1) })
            is ControlValue.ObjectValue -> JsonObject(value.values.mapValues { encodeValue(it.value, depth + 1) })
        }
    }

    private fun decodeObject(value: JsonElement?): Map<String, ControlValue> =
        (value as? JsonObject ?: invalid()).mapValues { decodeValue(it.value) }

    private fun decodeValue(value: JsonElement): ControlValue = when (value) {
        JsonNull -> ControlValue.Null
        is JsonObject -> ControlValue.ObjectValue(decodeObject(value))
        is JsonArray -> ControlValue.ArrayValue(value.map(::decodeValue))
        is JsonPrimitive -> when {
            value.isString -> ControlValue.Text(value.content)
            value.booleanOrNull != null -> ControlValue.BooleanValue(value.booleanOrNull!!)
            value.longOrNull != null -> ControlValue.IntegerValue(value.longOrNull!!)
            value.content.any { it == '.' || it == 'e' || it == 'E' } ->
                ControlValue.DecimalValue(value.doubleOrNull?.takeIf { it.isFinite() } ?: invalid())
            else -> invalid()
        }
    }

    private fun JsonObject.only(vararg fields: String) {
        if (keys.any { it !in fields }) invalid()
    }
    private fun JsonObject.text(key: String): String =
        (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()
    private fun JsonObject.optionalText(key: String): String? =
        if (get(key) == null || get(key) == JsonNull) null else text(key)
    private fun JsonObject.long(key: String): Long =
        (get(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: invalid()
    private fun JsonObject.optionalLong(key: String): Long? =
        if (get(key) == null || get(key) == JsonNull) null else long(key)
    private fun JsonObject.boolean(key: String): Boolean =
        (get(key) as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: invalid()
    private fun JsonObject.strings(key: String): List<String> =
        (get(key) as? JsonArray ?: invalid()).map {
            (it as? JsonPrimitive)?.takeIf { primitive -> primitive.isString }?.content ?: invalid()
        }

    private fun invalid(): Nothing = throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
    private inline fun <T> safeDecode(block: () -> T): T = try {
        block()
    } catch (error: ControlProtocolException) {
        throw error
    } catch (_: IllegalArgumentException) {
        // Serialization exceptions can quote credentials from malformed payloads.
        invalid()
    }
}
