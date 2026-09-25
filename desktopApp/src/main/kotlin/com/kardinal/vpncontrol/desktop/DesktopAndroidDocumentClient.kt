package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeoutException

/** Bounded ADB frames carry one immutable logical request/result; no private content enters argv. */
internal class DesktopAndroidDocumentClient(
    private val content: (List<String>, ByteArray, Boolean) -> String,
    private val remaining: () -> Long,
) {
    internal class Uncertain(val result: ControlResult) : Exception(result.code.wireName)

    fun exchange(bindOwner: (String) -> ControlRequest, submitted: () -> Unit): ControlResult? {
        var inputId: String? = null
        var boundRequest: ControlRequest? = null
        var documentOwner: String? = null
        var submissionAttempted = false
        var bytes = byteArrayOf()
        fun call(method: String, argument: String, cleanup: Boolean = false) =
            content(listOf("call", "--uri", URI, "--method", method, "--arg", argument), byteArrayOf(), cleanup)
        fun uncertain(code: ControlCode): ControlResult? {
            val id = inputId ?: return null
            val request = boundRequest ?: return null
            val owner = documentOwner ?: return null
            if (!submissionAttempted || request.controllerId != null && request.controllerId != owner) return null
            // The original deadline may have expired. One independent, bounded observation
            // can recover immutable identity, but never turns an unread result into success.
            val metadata = runCatching { bundle(call("document-result-status", id, cleanup = true)) }.getOrNull()
            val required = setOf("id", "state", "controllerId", "requestId", "configurationRevision")
            val valid = metadata != null && metadata.keys in setOf(required, required + "operationId") &&
                metadata["id"] == id && metadata["state"] == "complete" &&
                metadata["controllerId"] == owner && metadata["requestId"] == request.requestId
            val revision = if (valid) runCatching { number(metadata!!.getValue("configurationRevision")) }.getOrNull() else null
            val operation = if (revision != null) metadata?.get("operationId")?.let { runCatching { opaque(it) }.getOrNull() } else null
            val knownOperation = if (request.command.operation in setOf(ControlOperationId.OPERATIONS_WAIT,
                    ControlOperationId.OPERATIONS_STATUS, ControlOperationId.OPERATIONS_CANCEL))
                (request.command.arguments["id"] as? ControlValue.Text)?.value else null
            val metadataValid = revision != null && (metadata?.containsKey("operationId") != true || operation != null) &&
                (knownOperation == null || operation == null || operation == knownOperation)
            return ControlResult(owner, request.requestId, code, if (metadataValid) revision!! else 0,
                final = false, operationId = knownOperation ?: if (metadataValid) operation else null)
        }
        try {
            val begin = try { bundle(call("document-begin", UUID.randomUUID().toString())) }
                catch (error: DesktopAndroidAdbClient.AdbFailure) {
                    if (error.code == ControlCode.UNSUPPORTED) return null else throw error
                }
            if (begin == mapOf("error" to "UNSUPPORTED")) return null
            requireKeys(begin, "id", "controllerId", "chunkBytes")
            val id = opaque(begin.getValue("id")); inputId = id
            val owner = begin.getValue("controllerId")
            check(owner.isNotBlank() && owner.length <= 256 && owner.none(Char::isISOControl))
            documentOwner = owner
            val chunkSize = number(begin.getValue("chunkBytes")).also { check(it in 1..65536) }.toInt()
            val request = bindOwner(owner)
            boundRequest = request
            bytes = ControlDocumentCodec.encodeRequest(request).toByteArray(Charsets.UTF_8)
            var offset = 0
            while (offset < bytes.size) {
                val count = minOf(chunkSize, bytes.size - offset)
                val chunk = bytes.copyOfRange(offset, offset + count)
                try {
                    check(content(listOf("write", "--uri", "$URI/document-uploads/$id/$offset"), chunk, false).isBlank())
                } finally { chunk.fill(0) }
                offset += count
            }
            val inputHash = sha256(bytes)
            val sealed = bundle(call("document-seal", "$id:${bytes.size}:$inputHash"))
            requireKeys(sealed, "id", "byteCount", "sha256", "chunkBytes")
            check(sealed["id"] == id && number(sealed.getValue("byteCount")) == bytes.size.toLong() &&
                sealed["sha256"] == inputHash && number(sealed.getValue("chunkBytes")) == chunkSize.toLong())
            submitted()
            submissionAttempted = true
            var state = bundle(call("document-submit", id))
            while (true) {
                requireKeys(state, "state")
                when (state["state"]) {
                    "complete", "failed" -> break
                    "pending" -> Thread.sleep(minOf(100L, remaining()))
                    else -> incompatible()
                }
                state = bundle(call("document-status", id))
            }
            val descriptor = bundle(call("document-result", id))
            requireKeys(descriptor, "id", "byteCount", "sha256", "chunkBytes")
            val outputId = opaque(descriptor.getValue("id"))
            val count = number(descriptor.getValue("byteCount"))
            val hash = descriptor.getValue("sha256").also { check(Regex("[0-9a-f]{64}").matches(it)) }
            val readSize = number(descriptor.getValue("chunkBytes")).also { check(it in 1..65536) }.toInt()
            val digest = MessageDigest.getInstance("SHA-256")
            val output = ByteArrayOutputStream()
            var read = 0L
            while (read < count) {
                val length = minOf(readSize.toLong(), count - read).toInt()
                val chunk = bundle(call("document-read", "$id:$read:$length"))
                requireKeys(chunk, "id", "offset", "data")
                check(chunk["id"] == outputId && number(chunk.getValue("offset")) == read)
                val encoded = chunk.getValue("data")
                val decoded = try { Base64.getDecoder().decode(encoded) } catch (_: IllegalArgumentException) { incompatible() }
                try {
                    check(decoded.size == length && Base64.getEncoder().encodeToString(decoded) == encoded)
                    digest.update(decoded); output.write(decoded)
                } finally { decoded.fill(0) }
                read += length
            }
            check(digest.digest().joinToString("") { "%02x".format(it) } == hash)
            val document = output.toByteArray()
            val result = try { ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient.strictUtf8(document)) }
                catch (_: IllegalArgumentException) { incompatible() } finally { document.fill(0) }
            check(result.controllerId == owner && result.requestId == request.requestId)
            return result
        } catch (error: DesktopAndroidAdbClient.AdbFailure) {
            if (error.code == ControlCode.OUTCOME_UNKNOWN) uncertain(error.code)?.let { throw Uncertain(it) }
            throw error
        } catch (error: TimeoutException) {
            uncertain(ControlCode.TIMEOUT)?.let { throw Uncertain(it) }
            throw error
        } finally {
            bytes.fill(0)
            // BUSY during accepted domain work is deliberate: disconnect does not cancel it.
            inputId?.let { runCatching { call("document-discard", it, cleanup = true) } }
        }
    }

    private fun check(value: Boolean) { if (!value) incompatible() }
    private fun requireKeys(value: Map<String, String>, vararg keys: String) = check(value.keys == keys.toSet())
    private fun number(value: String): Long {
        check(Regex("0|[1-9][0-9]*").matches(value))
        return value.toLongOrNull() ?: incompatible()
    }
    private fun opaque(value: String): String {
        check(runCatching { UUID.fromString(value).toString() }.getOrNull() == value)
        return value
    }
    private fun bundle(value: String) = DesktopAndroidAdbClient.bundle(value)
    private fun incompatible(): Nothing = throw DesktopAndroidAdbClient.AdbFailure(ControlCode.INCOMPATIBLE_PROTOCOL)
    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
    private companion object { const val URI = "content://com.kardinal.vpncontrol.control" }
}
