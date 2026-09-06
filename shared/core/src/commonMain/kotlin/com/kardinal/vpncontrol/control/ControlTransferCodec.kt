package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/** Independent internal DTO codec; authentication and purpose admission belong to the adapter. */
@OptIn(ExperimentalEncodingApi::class)
object ControlTransferCodec {
    fun encode(command: ControlTransferCommand): String {
        val values = when (command) {
            is ControlTransferCommand.Begin -> mapOf("action" to text("begin"), "requestId" to text(command.requestId))
            is ControlTransferCommand.Append -> {
                valid(command.bytes.size in 1..ControlTransferLimits.CHUNK_BYTES)
                mapOf("action" to text("append"), "id" to text(command.id), "offset" to number(command.offset), "bytes" to text(Base64.encode(command.bytes)))
            }
            is ControlTransferCommand.Seal -> mapOf("action" to text("seal"), "id" to text(command.id), "byteCount" to number(command.byteCount), "sha256" to text(command.sha256))
            is ControlTransferCommand.Read -> mapOf("action" to text("read"), "id" to text(command.id), "offset" to number(command.offset), "length" to number(command.length.toLong()))
            is ControlTransferCommand.Discard -> mapOf("action" to text("discard"), "id" to text(command.id))
        }
        return ControlProtocolCodec.encodeValues(values).also { decode(it) }
    }

    fun decode(frame: String): ControlTransferCommand = safe {
        val values = values(frame)
        fun string(key: String) = (values[key] as? ControlValue.Text)?.value ?: invalid()
        fun integer(key: String) = (values[key] as? ControlValue.IntegerValue)?.value?.takeIf { it >= 0 } ?: invalid()
        fun keys(vararg keys: String) = valid(values.keys == keys.toSet())
        fun id() = string("id").also { valid(ID.matches(it)) }
        when (string("action")) {
            "begin" -> { keys("action", "requestId"); ControlTransferCommand.Begin(string("requestId").also { valid(it.isNotBlank() && it.length <= 128) }) }
            "append" -> {
                keys("action", "id", "offset", "bytes")
                val encoded = string("bytes")
                valid(encoded.length <= ((ControlTransferLimits.CHUNK_BYTES + 2) / 3) * 4)
                val bytes = Base64.decode(encoded)
                valid(bytes.size in 1..ControlTransferLimits.CHUNK_BYTES && Base64.encode(bytes) == encoded)
                ControlTransferCommand.Append(id(), integer("offset"), bytes)
            }
            "seal" -> { keys("action", "id", "byteCount", "sha256"); ControlTransferCommand.Seal(id(), integer("byteCount"), string("sha256").also { valid(HASH.matches(it)) }) }
            "read" -> { keys("action", "id", "offset", "length"); ControlTransferCommand.Read(id(), integer("offset"), integer("length").also { valid(it <= ControlTransferLimits.CHUNK_BYTES) }.toInt()) }
            "discard" -> { keys("action", "id"); ControlTransferCommand.Discard(id()) }
            else -> invalid()
        }
    }

    fun encodeManifest(manifest: ControlTransferManifest): String = ControlProtocolCodec.encodeValues(mapOf(
        "id" to text(manifest.id), "byteCount" to number(manifest.byteCount),
        "sha256" to (manifest.sha256?.let(::text) ?: ControlValue.Null), "chunkBytes" to number(manifest.chunkBytes.toLong()),
    )).also { decodeManifest(it) }

    fun encodeChunk(chunk: ControlTransferChunk): String {
        valid(chunk.bytes.size <= ControlTransferLimits.CHUNK_BYTES)
        return ControlProtocolCodec.encodeValues(mapOf("id" to text(chunk.id), "offset" to number(chunk.offset),
            "bytes" to text(Base64.encode(chunk.bytes)))).also { decodeChunk(it) }
    }

    fun decodeChunk(frame: String): ControlTransferChunk = safe {
        val values = values(frame)
        valid(values.keys == setOf("id", "offset", "bytes"))
        val id = (values["id"] as? ControlValue.Text)?.value ?: invalid()
        val offset = (values["offset"] as? ControlValue.IntegerValue)?.value ?: invalid()
        val encoded = (values["bytes"] as? ControlValue.Text)?.value ?: invalid()
        valid(ID.matches(id) && offset >= 0 && encoded.length <= ((ControlTransferLimits.CHUNK_BYTES + 2) / 3) * 4)
        val bytes = Base64.decode(encoded)
        valid(bytes.size <= ControlTransferLimits.CHUNK_BYTES && Base64.encode(bytes) == encoded)
        ControlTransferChunk(id, offset, bytes)
    }

    fun decodeManifest(frame: String): ControlTransferManifest = safe {
        val values = values(frame)
        valid(values.keys == setOf("id", "byteCount", "sha256", "chunkBytes"))
        val id = (values["id"] as? ControlValue.Text)?.value ?: invalid()
        val size = (values["byteCount"] as? ControlValue.IntegerValue)?.value ?: invalid()
        val chunk = (values["chunkBytes"] as? ControlValue.IntegerValue)?.value ?: invalid()
        val hash = when (val value = values["sha256"]) { ControlValue.Null -> null; is ControlValue.Text -> value.value.also { valid(HASH.matches(it)) }; else -> invalid() }
        valid(ID.matches(id) && size >= 0 && chunk in 1..ControlTransferLimits.CHUNK_BYTES.toLong())
        ControlTransferManifest(id, size, hash, chunk.toInt())
    }
    private fun values(frame: String): Map<String, ControlValue> {
        valid(frame.length <= ControlTransferLimits.FRAME_BYTES && frame.encodeToByteArray().size <= ControlTransferLimits.FRAME_BYTES)
        return ControlProtocolCodec.decodeValues(frame)
    }
    private fun text(value: String) = ControlValue.Text(value)
    private fun number(value: Long) = ControlValue.IntegerValue(value)
    private inline fun <T> safe(block: () -> T): T = try { block() } catch (_: Exception) { invalid() }
    private fun valid(value: Boolean) { if (!value) invalid() }
    private fun invalid(): Nothing = throw ControlProtocolException(ControlCode.INVALID_ARGUMENT)
    private val ID = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    private val HASH = Regex("[0-9a-f]{64}")
}
