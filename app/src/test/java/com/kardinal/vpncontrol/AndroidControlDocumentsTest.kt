package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import org.junit.Assert.*
import org.junit.Test

class AndroidControlDocumentsTest {
    private fun hash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    @Test fun streamingResultMatchesLegacyBytesAcrossUnicodeAndChunkBoundaries() {
        val directory = Files.createTempDirectory("android-documents-streaming")
        try {
            AndroidControlDocuments("owner", { AndroidControlTransferSpool.create(directory) }).use { documents ->
                val transfer = documents.begin(2000, UUID.randomUUID().toString())
                val input = "{}".toByteArray()
                documents.append(2000, transfer.id, 0, input)
                documents.seal(2000, transfer.id, input.size.toLong(), hash(input))
                requireNotNull(documents.claim(2000, transfer.id)).close()
                val result = ControlResult("owner", "request", ControlCode.OK, 7,
                    data = mapOf("all" to ControlValue.Text(buildString { for (code in 0..65535) append(code.toChar()) }.repeat(2))),
                    warnings = listOf("one", "東京"), restartRequired = true)
                val expected = ControlDocumentCodec.encodeResult(result).toByteArray(Charsets.UTF_8)
                documents.complete(2000, transfer.id, result)
                val output = documents.result(2000, transfer.id)
                assertEquals(expected.size.toLong(), output.byteCount)
                assertEquals(hash(expected), output.sha256)
                var offset = 0
                while (offset < expected.size) {
                    val length = minOf(65536, expected.size - offset)
                    assertArrayEquals(expected.copyOfRange(offset, offset + length), documents.read(2000, transfer.id, offset.toLong(), length).bytes)
                    offset += length
                }
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun resultStorageFailureDoesNotRepeatAnAlreadyCommittedOwnerRequest() = kotlinx.coroutines.test.runTest {
        val directory = Files.createTempDirectory("android-documents-result-failure")
        var committed = ControlCommitted("owner", 0, PersistedState())
        var writes = 0
        val control = AndroidSettingsControl("owner", backgroundScope, { committed }, { _, owner, revision ->
            check(owner == "owner" && revision == committed.revision)
            committed = committed.copy(revision = committed.revision + 1,
                value = committed.value.copy(appMode = AppMode.PROXY_ONLY))
            writes++
            AndroidSettingsCommit(committed, false)
        }, {}, { false })
        val request = ControlRequest("durable-request", ControlCommand(ControlOperationId.SETTINGS_SET,
                mapOf("key" to ControlValue.Text("mode"), "value" to ControlValue.Text("proxy-only"))),
            controllerId = "owner", ifRevision = 0)
        val reader = AndroidControlReader("owner", { committed.value }, settingsWrite = control::execute)
        val requestBytes = ControlDocumentCodec.encodeRequest(request).toByteArray()
        var creates = 0
        try {
            AndroidControlDocuments("owner", {
                if (++creates == 2) error("PRIVATE_DISK_PATH")
                AndroidControlTransferSpool.create(directory)
            }).use { documents ->
                suspend fun submit(): Pair<String, ByteArray> {
                    val input = documents.begin(2000, UUID.randomUUID().toString())
                    documents.append(2000, input.id, 0, requestBytes)
                    documents.seal(2000, input.id, requestBytes.size.toLong(), hash(requestBytes))
                    val bytes = requireNotNull(documents.claim(2000, input.id)).use { reader.executeDocument(it.bytes(), input.id) }
                    return input.id to bytes
                }
                val first = submit()
                assertEquals(ControlCode.PERSISTENCE_FAILED,
                    assertThrows(ControlProtocolException::class.java) { documents.complete(2000, first.first, first.second) }.code)
                assertEquals("failed", documents.state(2000, first.first))
                documents.discard(2000, first.first)
                val retry = submit()
                assertArrayEquals(first.second, retry.second)
                documents.complete(2000, retry.first, retry.second)
                assertEquals("complete", documents.state(2000, retry.first))
                assertEquals(1, writes)
                assertEquals(1L, committed.revision)
                assertEquals(AppMode.PROXY_ONLY, committed.value.appMode)
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun uploadUriNeverAllowsPathsAliasesOrOffsetOverflow() {
        val authority = "com.kardinal.vpncontrol.control"
        val id = UUID.randomUUID().toString()
        val prefix = "content://$authority/document-uploads/$id"
        assertEquals(id to 65536L, AndroidControlAccess.parseDocumentUpload("$prefix/65536", authority))
        for (uri in listOf("$prefix/-1", "$prefix/+1", "$prefix/01", "$prefix/9223372036854775808",
            "$prefix/1?offset=0", "$prefix/1#fragment", "$prefix/1/", "$prefix/%31", "$prefix/../1",
            "content://user@$authority/document-uploads/$id/0", "content://$authority.evil/document-uploads/$id/0")) {
            assertThrows(IllegalArgumentException::class.java) { AndroidControlAccess.parseDocumentUpload(uri, authority) }
        }
    }

    @Test fun unsealedOrMalformedInputNeverGetsAnExecutionClaim() {
        val directory = Files.createTempDirectory("android-documents-invalid")
        try {
            AndroidControlDocuments("owner", { AndroidControlTransferSpool.create(directory) }).use { documents ->
                val input = documents.begin(2000, UUID.randomUUID().toString())
                assertThrows(IllegalStateException::class.java) { documents.claim(2000, input.id) }
                assertThrows(ControlProtocolException::class.java) { documents.append(2000, input.id, 0, byteArrayOf(0xff.toByte())) }
                assertThrows(ControlProtocolException::class.java) { documents.append(2000, input.id, 1, byteArrayOf(65)) }
                documents.append(2000, input.id, 0, byteArrayOf(65))
                documents.seal(2000, input.id, 1, hash(byteArrayOf(65)))
                assertThrows(SecurityException::class.java) { documents.claim(10123, input.id) }
                requireNotNull(documents.claim(2000, input.id)).use {
                    documents.failed(2000, input.id)
                    assertEquals("failed", documents.state(2000, input.id))
                    val error = assertThrows(IllegalStateException::class.java) { documents.result(2000, input.id) }
                    assertEquals("OUTCOME_UNKNOWN", error.message)
                }
                documents.discard(2000, input.id)
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun largePrivateUploadSealExecuteAndDownloadKeepExactBytes() {
        val directory = Files.createTempDirectory("android-documents-東京")
        try {
            AndroidControlDocuments("owner", { AndroidControlTransferSpool.create(directory) }).use { documents ->
                val context = UUID.randomUUID().toString()
                val input = documents.begin(2000, context)
                assertEquals(input, documents.begin(2000, context))
                val payload = "東京\\\"\n".repeat(1_600_000).toByteArray(Charsets.UTF_8)
                var offset = 0
                while (offset < payload.size) {
                    val chunk = payload.copyOfRange(offset, minOf(payload.size, offset + 65536))
                    val first = documents.append(2000, input.id, offset.toLong(), chunk)
                    assertEquals(first, documents.append(2000, input.id, offset.toLong(), chunk))
                    offset += chunk.size
                }
                assertThrows(ControlProtocolException::class.java) { documents.seal(2000, input.id, payload.size.toLong(), "0".repeat(64)) }
                val sealed = documents.seal(2000, input.id, payload.size.toLong(), hash(payload))
                assertEquals(sealed, documents.seal(2000, input.id, payload.size.toLong(), hash(payload)))
                val consumer = requireNotNull(documents.claim(2000, input.id))
                consumer.use {
                    assertNull(documents.claim(2000, input.id))
                    assertThrows(IllegalStateException::class.java) { documents.discard(2000, input.id) }
                    assertArrayEquals(payload, it.bytes())
                    documents.complete(2000, input.id, payload)
                }
                val result = documents.result(2000, input.id)
                assertEquals(sealed.byteCount, result.byteCount)
                assertEquals(sealed.sha256, result.sha256)
                val digest = MessageDigest.getInstance("SHA-256")
                var read = 0L
                while (read < result.byteCount) {
                    val chunk = documents.read(2000, input.id, read, minOf(65536L, result.byteCount - read).toInt())
                    assertEquals(result.id, chunk.id)
                    assertEquals(read, chunk.offset)
                    digest.update(chunk.bytes)
                    read += chunk.bytes.size
                }
                assertEquals(result.sha256, digest.digest().joinToString("") { "%02x".format(it) })
                assertNull(documents.claim(2000, input.id))
                assertEquals("complete", documents.state(2000, input.id))
                documents.discard(2000, input.id)
                documents.discard(2000, input.id)
                Files.list(directory).use { assertEquals(0L, it.count()) }
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun callerIdentityAndExpiryCannotResurrectOrEraseAnActiveConsumer() {
        val directory = Files.createTempDirectory("android-documents-expiry")
        var now = 0L
        try {
            AndroidControlDocuments("owner", { AndroidControlTransferSpool.create(directory) }, { now }, capacity = 1, idleMillis = 100).use { documents ->
                val input = documents.begin(2000, UUID.randomUUID().toString())
                assertThrows(SecurityException::class.java) { documents.append(10123, input.id, 0, byteArrayOf(65)) }
                assertThrows(SecurityException::class.java) { documents.discard(10123, input.id) }
                assertThrows(IllegalStateException::class.java) { documents.begin(2000, UUID.randomUUID().toString()) }
                documents.append(2000, input.id, 0, byteArrayOf(65))
                documents.seal(2000, input.id, 1, hash(byteArrayOf(65)))
                requireNotNull(documents.claim(2000, input.id)).use { consumer ->
                    now = 100
                    documents.begin(2000, UUID.randomUUID().toString())
                    assertArrayEquals(byteArrayOf(65), consumer.bytes())
                    assertThrows(IllegalStateException::class.java) { documents.complete(2000, input.id, byteArrayOf(65)) }
                }
            }
        } finally { directory.toFile().deleteRecursively() }
    }
}
