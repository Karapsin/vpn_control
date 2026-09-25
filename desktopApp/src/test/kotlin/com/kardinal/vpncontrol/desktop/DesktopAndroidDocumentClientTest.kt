package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeoutException
import kotlin.test.*

class DesktopAndroidDocumentClientTest {
    @Test fun runtimeContinuationCannotAdoptReplacementOwner() {
        val fixture = Fixture("payload", "continuation-owner")
        val request = ControlRequest("on", ControlCommand(ControlOperationId.ON))
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 20).message)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
        assertEquals(OUTPUT, result.operationId)
        assertEquals(2, fixture.submissions)
    }
    @Test fun unicodeDocumentsOverTenMiBRoundTripThroughBoundedPrivateChunks() {
        val document = "東京🙂private-document".repeat(500_000)
        val fixture = Fixture(document)
        val request = ControlRequest("large", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
            mapOf("input" to ControlValue.Text(document))))
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 60).message)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(42, result.configurationRevision)
        assertEquals(document, (result.data["document"] as ControlValue.Text).value)
        assertEquals(request.copy(controllerId = "owner"), fixture.request)
        assertTrue(fixture.chunks > 100)
        assertEquals(1, fixture.submissions)
        assertEquals(1, fixture.discards)
        assertTrue(fixture.commands.none { it.any { token -> "private-document" in token } })
    }

    @Test fun badSealNeverSubmitsAndBadDownloadsNeverReplay() {
        for (mode in listOf("seal", "offset", "output-id", "digest", "utf8", "owner", "request-id", "descriptor-overflow")) {
            val fixture = Fixture("payload", mode)
            val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request(), "test", 20).message)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, result.code, mode)
            assertEquals(if (mode == "seal") 0 else 1, fixture.submissions, mode)
            assertEquals(1, fixture.discards, mode)
            assertFalse(fixture.commands.any { "create" in it || "cancel" in it }, mode)
        }
    }

    @Test fun timeoutAfterSubmissionRetainsKnownOperationAndOnlyDiscardsTransport() {
        val fixture = Fixture("payload", "timeout")
        val request = ControlRequest("wait", ControlCommand(ControlOperationId.OPERATIONS_WAIT,
            mapOf("id" to ControlValue.Text(INPUT))))
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 20).message)
        assertEquals(ControlCode.TIMEOUT, result.code)
        assertEquals(INPUT, result.operationId)
        assertEquals(1, fixture.submissions)
        assertEquals(1, fixture.discards)
    }

    @Test fun committedDocumentReadLossRetainsAuthenticatedOwnerAndRequestWithoutInventingOperation() {
        val fixture = Fixture("payload", "read-loss")
        val request = ControlRequest("lost-read", ControlCommand(ControlOperationId.ROUTING_SET,
            mapOf("key" to ControlValue.Text("ignore-rules"), "value" to ControlValue.Text("true"))),
            controllerId = "owner", ifRevision = 41)
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 20).message)
        assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
        assertFalse(result.final)
        assertEquals("lost-read", result.requestId)
        assertEquals("owner", result.controllerId)
        assertNull(result.operationId) // The provider exposes it only in the unread result document.
        assertEquals(1, fixture.submissions)
        assertEquals(1, fixture.discards)
        assertEquals(1, fixture.commands.count { "document-read" in it })
    }

    @Test fun committedDocumentReadLossRecoversOnlyMatchingPublishedOperationMetadata() {
        for (mode in listOf("read-loss-metadata", "read-loss-owner", "read-loss-request",
            "read-loss-transfer", "read-loss-operation", "read-loss-revision")) {
            val fixture = Fixture("payload", mode)
            val request = ControlRequest("lost-read", ControlCommand(ControlOperationId.ROUTING_SET,
                mapOf("key" to ControlValue.Text("ignore-rules"), "value" to ControlValue.Text("true"))),
                controllerId = "owner", ifRevision = 41)
            val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 20).message)
            assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code, mode)
            assertFalse(result.final, mode)
            assertEquals("lost-read", result.requestId, mode)
            assertEquals("owner", result.controllerId, mode)
            assertEquals(if (mode == "read-loss-metadata") OUTPUT else null, result.operationId, mode)
            assertEquals(if (mode == "read-loss-metadata") 42L else 0L, result.configurationRevision, mode)
            assertEquals(1, fixture.submissions, mode)
            assertEquals(1, fixture.discards, mode)
            assertEquals(1, fixture.commands.count { "document-result-status" in it }, mode)
        }
    }

    @Test fun expiredDocumentReadKeepsKnownWaitOperationWithoutContinuing() {
        val fixture = Fixture("payload", "read-loss-expired")
        val request = ControlRequest("expired-read", ControlCommand(ControlOperationId.OPERATIONS_WAIT,
            mapOf("id" to ControlValue.Text(INPUT))), controllerId = "owner")
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 1).message)
        assertEquals(ControlCode.TIMEOUT, result.code)
        assertEquals("owner", result.controllerId)
        assertEquals("expired-read", result.requestId)
        assertEquals(INPUT, result.operationId)
        assertFalse(result.final)
        assertEquals(1, fixture.submissions)
        assertEquals(1, fixture.commands.count { "document-result-status" in it })
        assertEquals(1, fixture.discards)
    }

    @Test fun explicitStaleOwnerIsNotReboundAndCurrentOwnerConflictIsPreserved() {
        val fixture = Fixture("payload", "conflict")
        val request = request().copy(controllerId = "stale", ifRevision = 9)
        val result = ControlDocumentCodec.decodeResult(DesktopAndroidAdbClient(fixture::execute).request(request, "test", 20).message)
        assertEquals(request, fixture.request)
        assertEquals(ControlCode.CONFLICT, result.code)
        assertEquals("owner", result.controllerId)
    }

    @Test fun onlyKnownUnsupportedBeginAllowsLegacyFallbackAndLargeInputNeverWritesLegacy() {
        for (error in listOf("java.lang.IllegalArgumentException: UNSUPPORTED\n", "java.lang.IllegalStateException: unavailable\n")) {
            val commands = mutableListOf<List<String>>()
            val client = DesktopAndroidAdbClient { args, _, _ ->
                commands += args
                if (args == listOf("devices")) response("List of devices attached\ntest\tdevice\n")
                else DesktopAdbProcessResult(1, byteArrayOf(), error.toByteArray())
            }
            val large = request().copy(command = ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text("x".repeat(1_100_000)))))
            val result = ControlDocumentCodec.decodeResult(client.request(large, "test", 20).message)
            assertEquals(if ("UNSUPPORTED" in error) ControlCode.INCOMPATIBLE_PROTOCOL else ControlCode.UNAVAILABLE, result.code)
            assertEquals(2, commands.size)
        }
    }

    private fun request() = ControlRequest("request", ControlCommand(ControlOperationId.SETTINGS_SHOW))
    private class Fixture(val document: String, val mode: String = "") {
        val commands = mutableListOf<List<String>>()
        val upload = ByteArrayOutputStream()
        var request: ControlRequest? = null
        var output = byteArrayOf()
        var chunks = 0; var submissions = 0; var discards = 0; var begins = 0
        fun execute(args: List<String>, input: ByteArray, timeout: Long): DesktopAdbProcessResult {
            assertTrue(timeout > 0)
            commands += args
            if (args == listOf("devices")) return response("List of devices attached\ntest\tdevice\n")
            assertEquals(listOf("-s", "test", "shell", "-T", "content"), args.take(5))
            if (args[5] == "write") {
                assertTrue(input.size in 1..65536)
                assertEquals(upload.size().toString(), args.last().substringAfterLast('/'))
                upload.write(input); chunks++
                return response("")
            }
            val method = args[9]
            return response(when (method) {
                "document-begin" -> {
                    begins++; upload.reset()
                    bundle("id" to INPUT, "controllerId" to if (mode == "continuation-owner" && begins > 1) "replacement" else "owner", "chunkBytes" to "65536")
                }
                "document-seal" -> {
                    val parts = args.last().split(':')
                    assertEquals(INPUT, parts[0]); assertEquals(upload.size().toString(), parts[1]); assertEquals(hash(upload.toByteArray()), parts[2])
                    request = ControlDocumentCodec.decodeRequest(upload.toString(Charsets.UTF_8))
                    bundle("id" to INPUT, "byteCount" to parts[1], "sha256" to if (mode == "seal") "0".repeat(64) else parts[2], "chunkBytes" to "65536")
                }
                "document-submit" -> {
                    submissions++
                    if (mode == "timeout") throw TimeoutException()
                    val continuation = mode == "continuation-owner"
                    val result = ControlResult(if (mode == "owner" || continuation && begins > 1) "replacement" else "owner",
                        if (mode == "request-id") "different" else requireNotNull(request).requestId,
                        if (continuation) { if (begins == 1) ControlCode.ACCEPTED else ControlCode.CONFLICT }
                            else if (mode == "conflict") ControlCode.CONFLICT else ControlCode.OK, 42,
                        final = !continuation || begins > 1, operationId = if (continuation || mode.startsWith("read-loss")) OUTPUT else null,
                        data = mapOf("document" to ControlValue.Text(document)))
                    output = if (mode == "utf8") byteArrayOf(0xc3.toByte(), 0x28) else ControlDocumentCodec.encodeResult(result).toByteArray()
                    bundle("state" to "complete")
                }
                "document-result" -> bundle("id" to OUTPUT,
                    "byteCount" to if (mode == "descriptor-overflow") "9223372036854775808" else output.size.toString(),
                    "sha256" to if (mode == "digest") "0".repeat(64) else hash(output), "chunkBytes" to "65536")
                "document-result-status" -> {
                    if (mode == "read-loss") return DesktopAdbProcessResult(1, byteArrayOf(),
                        "java.lang.IllegalArgumentException: UNSUPPORTED".toByteArray())
                    if (mode == "timeout") return response(bundle("id" to INPUT, "state" to "pending"))
                    bundle("id" to if (mode == "read-loss-transfer") OUTPUT else INPUT,
                        "state" to "complete", "controllerId" to if (mode == "read-loss-owner") "replacement" else "owner",
                        "requestId" to if (mode == "read-loss-request") "different" else requireNotNull(request).requestId,
                        "configurationRevision" to if (mode == "read-loss-revision") "bad" else "42",
                        "operationId" to if (mode == "read-loss-operation") "not-an-id" else OUTPUT)
                }
                "document-read" -> {
                    if (mode == "read-loss-expired") { Thread.sleep(1100); throw TimeoutException() }
                    if (mode.startsWith("read-loss")) return DesktopAdbProcessResult(74, byteArrayOf(), "response lost".toByteArray())
                    val parts = args.last().split(':'); val offset = parts[1].toInt(); val length = parts[2].toInt()
                    assertEquals(INPUT, parts[0]); assertTrue(length in 1..65536)
                    bundle("id" to if (mode == "output-id") INPUT else OUTPUT,
                        "offset" to if (mode == "offset") "99" else offset.toString(),
                        "data" to Base64.getEncoder().encodeToString(output.copyOfRange(offset, offset+length)))
                }
                "document-discard" -> { discards++; bundle("state" to "discarded") }
                else -> error("Unexpected method $method")
            })
        }
    }
    companion object {
        private const val INPUT = "11111111-1111-4111-8111-111111111111"
        private const val OUTPUT = "22222222-2222-4222-8222-222222222222"
        private fun response(value: String) = DesktopAdbProcessResult(0, value.toByteArray(), byteArrayOf())
        private fun bundle(vararg fields: Pair<String,String>) = "Result: Bundle[{" + fields.joinToString(", ") { "${it.first}=${it.second}" } + "}]"
        private fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
    }
}
