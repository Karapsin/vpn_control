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

/** Safe to report without leaking the malformed frame or an underlying parser exception. */
class ControlProtocolException(val code: ControlCode) : IllegalArgumentException(code.wireName)

/** JSON DTO codec only. Authentication, frame IO and streamed content belong to the adapter. */
object ControlProtocolCodec {
    const val MAX_FRAME_BYTES = 1_048_576
    private const val MAX_DEPTH = 32
    private val json = Json { isLenient = false }

    fun encodeValues(values: Map<String, ControlValue>): String = checkedEncode(encodeObject(values))
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

    fun decodeRequest(frame: String): ControlRequest = safeDecode {
        val root = parse(frame)
        checkVersion(root)
        root.only("schemaVersion", "requestId", "controllerId", "ifRevision", "interactive", "asynchronous", "command")
        val command = root["command"] as? JsonObject ?: invalid()
        command.only("operation", "arguments")
        ControlRequest(
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
        // Count bytes, not UTF-16 units. Bound nesting before asking the JSON parser to recurse.
        if (frame.length > MAX_FRAME_BYTES || frame.encodeToByteArray().size > MAX_FRAME_BYTES) invalid()
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
        if (frame.encodeToByteArray().size > MAX_FRAME_BYTES) invalid()
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
