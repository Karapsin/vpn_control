package com.kardinal.vpncontrol

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.Handler
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import android.util.Base64
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.model.ControlTransferManifest
import java.io.FileNotFoundException
import java.util.concurrent.atomic.AtomicInteger

/** Delegated only AFTER the exported provider authenticates Binder UID and permission. */
internal class AndroidControlDocumentProvider(
    private val context: Context,
    private val owner: () -> AndroidApplicationOwner,
    private val handler: Handler,
    private val descriptors: AtomicInteger,
) {
    fun call(uid: Int, method: String, arg: String?): Bundle? = sanitized {
        if (method !in METHODS) return@sanitized null
        val documents = owner().controlDocuments
        fun id() = AndroidControlAccess.opaqueId(requireNotNull(arg) { "INVALID_ARGUMENT" })
        fun fields(count: Int): List<String> = requireNotNull(arg) { "INVALID_ARGUMENT" }.split(':').also {
            require(it.size == count) { "INVALID_ARGUMENT" }
            AndroidControlAccess.opaqueId(it[0])
        }
        when (method) {
            "document-begin" -> {
                val input = documents.begin(uid, id())
                bundle("id" to input.id, "controllerId" to documents.controllerId, "chunkBytes" to input.chunkBytes.toString())
            }
            "document-seal" -> {
                val fields = fields(3)
                require(fields[2].matches(Regex("[0-9a-f]{64}"))) { "INVALID_ARGUMENT" }
                manifest(documents.seal(uid, fields[0], number(fields[1]), fields[2]))
            }
            "document-submit" -> {
                val id = id()
                documents.claim(uid, id)?.let { input ->
                    val job = owner().commands.launch {
                        try {
                            val response = input.stream().use { owner().controlReader.documentResponse(it, id) }
                            documents.complete(uid, id, response)
                        } catch (_: OutOfMemoryError) {
                            runCatching { documents.failed(uid, id) }
                        } catch (_: Exception) {
                            runCatching { documents.failed(uid, id) }
                        } finally { input.close() }
                    }
                    job.invokeOnCompletion { error ->
                        runCatching { input.close() }
                        if (error != null) runCatching { documents.failed(uid, id) }
                    }
                }
                bundle("state" to documents.state(uid, id))
            }
            "document-status" -> bundle("state" to documents.state(uid, id()))
            "document-result" -> manifest(documents.result(uid, id()))
            "document-read" -> {
                val fields = fields(3)
                val length = number(fields[2])
                require(length in 0..65536) { "INVALID_ARGUMENT" }
                val chunk = documents.read(uid, fields[0], number(fields[1]), length.toInt())
                try { bundle("id" to chunk.id, "offset" to chunk.offset.toString(),
                    "data" to Base64.encodeToString(chunk.bytes, Base64.NO_WRAP)) }
                finally { chunk.bytes.fill(0) }
            }
            "document-discard" -> { documents.discard(uid, id()); Bundle.EMPTY }
            else -> error("UNSUPPORTED")
        }
    }

    fun openUpload(uid: Int, uri: String, authority: String, mode: String): ParcelFileDescriptor = sanitized {
        require(mode == "w") { "INVALID_ARGUMENT" }
        val (id, baseOffset) = AndroidControlAccess.parseDocumentUpload(uri, authority)
        val documents = owner().controlDocuments
        check(documents.state(uid, id) == "uploading") { "CONFLICT" }
        if (descriptors.incrementAndGet() > 8) {
            descriptors.decrementAndGet()
            throw FileNotFoundException("BUSY")
        }
        try {
            val callback = object : ProxyFileDescriptorCallback() {
                private var invalid = false
                override fun onGetSize(): Long = checked { documents.state(uid, id); 0L }
                override fun onWrite(offset: Long, size: Int, data: ByteArray): Int = checked {
                    require(offset in 0..65536 && size in 1..data.size && size.toLong() <= 65536 - offset &&
                        baseOffset <= Long.MAX_VALUE - offset) { "INVALID_ARGUMENT" }
                    val bytes = data.copyOf(size)
                    try { documents.append(uid, id, baseOffset + offset, bytes); size }
                    finally { bytes.fill(0) }
                }
                override fun onFsync() { checked { documents.state(uid, id) } }
                override fun onRelease() { descriptors.decrementAndGet() }
                private fun <T> checked(action: () -> T): T = try {
                    check(!invalid)
                    action()
                } catch (_: Exception) {
                    invalid = true
                    throw ErrnoException("control", OsConstants.EIO)
                }
            }
            val token = Binder.clearCallingIdentity()
            try {
                context.getSystemService(StorageManager::class.java).openProxyFileDescriptor(
                    ParcelFileDescriptor.MODE_WRITE_ONLY, callback, handler)
            } finally { Binder.restoreCallingIdentity(token) }
        } catch (error: Exception) { descriptors.decrementAndGet(); throw error }
    }

    private fun number(value: String): Long {
        require(value.matches(Regex("0|[1-9][0-9]*"))) { "INVALID_ARGUMENT" }
        return value.toLongOrNull() ?: throw IllegalArgumentException("INVALID_ARGUMENT")
    }
    private fun manifest(value: ControlTransferManifest) = bundle("id" to value.id,
        "byteCount" to value.byteCount.toString(), "sha256" to requireNotNull(value.sha256), "chunkBytes" to value.chunkBytes.toString())
    private fun bundle(vararg fields: Pair<String, String>) = Bundle().apply { fields.forEach { putString(it.first, it.second) } }
    private fun <T> sanitized(block: () -> T): T = try { block() }
    catch (_: SecurityException) { throw SecurityException("PERMISSION_DENIED") }
    catch (error: ControlProtocolException) { throw IllegalArgumentException(error.code.wireName) }
    catch (error: Exception) {
        val code = error.message?.takeIf { it in setOf("INVALID_ARGUMENT", "CONFLICT", "BUSY", "NOT_FOUND", "OUTCOME_UNKNOWN", "UNAVAILABLE") }
            ?: "UNAVAILABLE"
        throw IllegalStateException(code)
    }
    companion object {
        private val METHODS = setOf("document-begin", "document-seal", "document-submit", "document-status",
            "document-result", "document-read", "document-discard")
    }
}
