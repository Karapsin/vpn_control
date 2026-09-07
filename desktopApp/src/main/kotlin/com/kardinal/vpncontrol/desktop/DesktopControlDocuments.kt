package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.io.InputStream
import java.io.InputStreamReader
import java.io.BufferedInputStream
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.runBlocking

/** Called only after endpoint authentication. References never name a filesystem path. */
internal class DesktopControlDocuments(private val owner: String) : AutoCloseable {
    private val store = ControlTransferStore(owner, { DesktopControlTransferSpool.create() },
        { UUID.randomUUID().toString() }, { System.nanoTime() / 1_000_000 })
    private data class Acknowledgement(val kind: String, val manifest: ControlTransferManifest, var touched: Long, var action: (() -> Unit)?)
    private val acknowledgements = mutableMapOf<String, Acknowledgement>()

    fun hasWork(): Boolean = try { runBlocking { store.hasRetainedTransfers() } } catch (_: Exception) { true }

    fun readContext(frame: String): Pair<String, String>? {
        if (!frame.startsWith(CONTEXT)) return null
        val values = envelope(frame.removePrefix(CONTEXT), "command")
        require(values.text("command").isEmpty() && values.text("kind") != "command")
        return values.text("context") to values.text("kind")
    }

    fun handle(frame: String): String? {
        if (!frame.startsWith(TRANSFER)) return null
        val envelope = envelope(frame.removePrefix(TRANSFER), "command")
        val context = envelope.text("context")
        val kind = envelope.text("kind")
        val binding = binding(context, kind)
        val command = envelope.text("command")
        if (command.startsWith("ack:")) {
            require(kind != "command")
            synchronized(acknowledgements) {
                val pending = acknowledgements[context]
                if (pending != null) {
                    require(pending.kind == kind && command == "ack:${pending.manifest.id}:${pending.manifest.sha256}")
                }
            }
            return "ACKNOWLEDGED"
        }
        return runBlocking {
            when (val action = ControlTransferCodec.decode(command)) {
                is ControlTransferCommand.Begin -> {
                    require(kind == "command" && action.requestId == context)
                    ControlTransferCodec.encodeManifest(store.begin(binding, action.requestId))
                }
                is ControlTransferCommand.Append -> {
                    require(kind == "command")
                    ControlTransferCodec.encodeManifest(store.append(binding, action.id, action.offset, action.bytes))
                }
                is ControlTransferCommand.Seal -> {
                    require(kind == "command")
                    ControlTransferCodec.encodeManifest(store.seal(binding, action.id, action.byteCount, action.sha256))
                }
                is ControlTransferCommand.Read -> {
                    require(kind != "command")
                    val bytes = store.read(binding, action.id, action.offset, action.length)
                    synchronized(acknowledgements) {
                        acknowledgements[context]?.takeIf { it.kind == kind && it.manifest.id == action.id }
                            ?.touched = System.nanoTime() / 1_000_000
                    }
                    try { ControlTransferCodec.encodeChunk(ControlTransferChunk(action.id, action.offset, bytes)) }
                    finally { bytes.fill(0) }
                }
                is ControlTransferCommand.Discard -> {
                    store.discard(binding, action.id)
                    synchronized(acknowledgements) {
                        if (acknowledgements[context]?.manifest?.id == action.id) acknowledgements.remove(context)
                    }
                    "DISCARDED"
                }
            }
        }
    }

    fun responseFlushed(frame: String) {
        if (!frame.startsWith(TRANSFER)) return
        val values = envelope(frame.removePrefix(TRANSFER), "command")
        if (!values.text("command").startsWith("ack:")) return
        val callback = synchronized(acknowledgements) {
            acknowledgements[values.text("context")]?.let { pending ->
                require(pending.kind == values.text("kind") &&
                    values.text("command") == "ack:${pending.manifest.id}:${pending.manifest.sha256}")
                pending.action.also { pending.action = null }
            }
        }
        callback?.invoke()
    }

    fun consume(frame: String, expectedContext: String? = null): String {
        if (!frame.startsWith(REFERENCE)) return frame
        val reference = envelope(frame.removePrefix(REFERENCE), "manifest")
        require(reference.text("kind") == "command")
        require(expectedContext == null || reference.text("context") == expectedContext)
        val binding = binding(reference.text("context"), "command")
        val manifest = ControlTransferCodec.decodeManifest(reference.text("manifest"))
        return runBlocking {
            val consumer = store.acquire(binding, manifest.id)
            try {
                require(consumer.manifest == manifest)
                readText(manifest) { offset, length -> runBlocking { consumer.read(offset, length) } }
            } finally { consumer.close() }
        }
    }

    fun publish(document: String, kind: String, context: String = UUID.randomUUID().toString(), onAcknowledged: () -> Unit): String = synchronized(acknowledgements) {
        val binding = binding(context, kind)
        val now = System.nanoTime() / 1_000_000
        acknowledgements.entries.removeAll { now - it.value.touched >= 300_000 }
        require(acknowledgements[context]?.kind?.let { it == kind } != false)
        val manifest = runBlocking {
            var entry = store.begin(binding, context)
            // A retry must not append to or discard an already sealed response.
            // Preserve its first lifecycle callback, including an already-flushed ACK.
            if (entry.sha256 != null) {
                val bytes = document.toByteArray(Charsets.UTF_8)
                try { require(entry.byteCount == bytes.size.toLong() && entry.sha256 == digest(bytes)) }
                finally { bytes.fill(0) }
                return@runBlocking entry
            }
            try {
                val bytes = document.toByteArray(Charsets.UTF_8)
                val hash = digest(bytes)
                try {
                    var offset = 0
                    while (offset < bytes.size) {
                        val chunk = bytes.copyOfRange(offset, minOf(bytes.size, offset + ControlTransferLimits.CHUNK_BYTES))
                        try { store.append(binding, entry.id, offset.toLong(), chunk) } finally { chunk.fill(0) }
                        offset += chunk.size
                    }
                    entry = store.seal(binding, entry.id, bytes.size.toLong(), hash)
                } finally { bytes.fill(0) }
                entry
            } catch (error: Exception) { runCatching { store.discard(binding, entry.id) }; throw error }
        }
        acknowledgements.getOrPut(context) { Acknowledgement(kind, manifest, now, onAcknowledged) }.touched = now
        reference(owner, context, kind, manifest)
    }

    private fun envelope(document: String, field: String): Map<String, ControlValue> {
        val values = ControlProtocolCodec.decodeValues(document)
        require(values.keys == setOf("owner", "context", "kind", field))
        require(values.text("owner") == owner)
        validContext(values.text("context"))
        require(values.text("kind") in KINDS)
        return values
    }

    private fun binding(context: String, kind: String): ControlTransferBinding {
        validContext(context); require(kind in KINDS)
        return ControlTransferBinding(owner, "authenticated-desktop-owner", if (kind == "command")
            ControlTransferPurpose.COMMAND_DOCUMENT else ControlTransferPurpose.RESPONSE_DOCUMENT, "$kind:$context")
    }

    override fun close() {
        synchronized(acknowledgements) { acknowledgements.clear() }
        runBlocking { store.close() }
    }

    companion object {
        const val TRANSFER = "vpn-control-transfer-v1\t"
        const val REFERENCE = "vpn-control-document-v1\t"
        const val CONTEXT = "vpn-control-context-v1\t"
        private val KINDS = setOf("command", "response", "snapshot", "presentation")
        private fun validContext(context: String) { require(UUID.fromString(context).toString() == context) }
        private fun Map<String, ControlValue>.text(key: String) = (getValue(key) as ControlValue.Text).value
        private fun fields(owner: String, context: String, kind: String, field: String, value: String) =
            ControlProtocolCodec.encodeValues(mapOf("owner" to ControlValue.Text(owner), "context" to ControlValue.Text(context),
                "kind" to ControlValue.Text(kind), field to ControlValue.Text(value)))
        fun command(owner: String, context: String, kind: String, command: ControlTransferCommand) =
            TRANSFER + fields(owner, context, kind, "command", ControlTransferCodec.encode(command))
        fun context(owner: String, context: String, kind: String): String = CONTEXT + fields(owner, context, kind, "command", "")
        private fun reference(owner: String, context: String, kind: String, manifest: ControlTransferManifest) =
            REFERENCE + fields(owner, context, kind, "manifest", ControlTransferCodec.encodeManifest(manifest))
        private fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

        fun upload(owner: String, document: String, context: String, exchange: (String) -> String): Pair<String, () -> Unit> {
            fun send(action: ControlTransferCommand) = exchange(command(owner, context, "command", action))
            val manifest = ControlTransferCodec.decodeManifest(send(ControlTransferCommand.Begin(context)))
            val discard = { send(ControlTransferCommand.Discard(manifest.id)); Unit }
            try {
                val bytes = document.toByteArray(Charsets.UTF_8)
                val sealed = try {
                    var offset = 0
                    while (offset < bytes.size) {
                        val chunk = bytes.copyOfRange(offset, minOf(bytes.size, offset + manifest.chunkBytes))
                        try {
                            val received = ControlTransferCodec.decodeManifest(send(ControlTransferCommand.Append(manifest.id, offset.toLong(), chunk)))
                            require(received.id == manifest.id && received.byteCount == offset.toLong() + chunk.size)
                        } finally { chunk.fill(0) }
                        offset += chunk.size
                    }
                    val hash = digest(bytes)
                    ControlTransferCodec.decodeManifest(send(ControlTransferCommand.Seal(manifest.id, bytes.size.toLong(), hash))).also {
                        require(it.id == manifest.id && it.byteCount == bytes.size.toLong() && it.sha256 == hash)
                    }
                } finally { bytes.fill(0) }
                return reference(owner, context, "command", sealed) to discard
            } catch (error: Exception) { runCatching(discard); throw error }
        }

        fun download(owner: String, frame: String, expectedKind: String, expectedContext: String, exchange: (String) -> String): String {
            if (!frame.startsWith(REFERENCE)) return frame
            val values = ControlProtocolCodec.decodeValues(frame.removePrefix(REFERENCE))
            require(values.keys == setOf("owner", "context", "kind", "manifest"))
            require(values.text("owner") == owner && values.text("kind") == expectedKind && expectedKind != "command")
            val context = values.text("context").also(::validContext)
            require(context == expectedContext)
            val manifest = ControlTransferCodec.decodeManifest(values.text("manifest"))
            require(manifest.sha256 != null)
            val hash = MessageDigest.getInstance("SHA-256")
            try {
                val document = readText(manifest) { offset, length ->
                    val chunk = ControlTransferCodec.decodeChunk(exchange(command(owner, context, expectedKind,
                        ControlTransferCommand.Read(manifest.id, offset, length))))
                    require(chunk.id == manifest.id && chunk.offset == offset && chunk.bytes.size == length)
                    hash.update(chunk.bytes)
                    chunk.bytes
                }
                require(hash.digest().joinToString("") { "%02x".format(it) } == manifest.sha256)
                require(exchange(TRANSFER + fields(owner, context, expectedKind, "command", "ack:${manifest.id}:${manifest.sha256}")) == "ACKNOWLEDGED")
                return document
            } finally { runCatching { exchange(command(owner, context, expectedKind, ControlTransferCommand.Discard(manifest.id))) } }
        }

        private fun readText(manifest: ControlTransferManifest, readChunk: (Long, Int) -> ByteArray): String {
            var offset = 0L
            val stream = object : InputStream() {
                override fun read(): Int = if (offset == manifest.byteCount) -1 else readChunk(offset++, 1).single().toInt() and 255
                override fun read(output: ByteArray, start: Int, size: Int): Int {
                    if (size == 0) return 0
                    if (offset == manifest.byteCount) return -1
                    val length = minOf(size.toLong(), manifest.chunkBytes.toLong(), manifest.byteCount - offset).toInt()
                    val bytes = readChunk(offset, length)
                    try { require(bytes.size == length); bytes.copyInto(output, start); offset += length; return length }
                    finally { bytes.fill(0) }
                }
            }
            return InputStreamReader(BufferedInputStream(stream, ControlTransferLimits.CHUNK_BYTES), Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)).use { it.readText() }
        }
    }
}
