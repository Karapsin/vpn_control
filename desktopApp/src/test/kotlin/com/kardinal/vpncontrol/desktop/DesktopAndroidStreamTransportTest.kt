package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Exercises the public stream path through the bounded Android document transport. */
class DesktopAndroidStreamTransportTest {
    @Test fun documentTransportFollowPinsOwnerAndCarriesOpaqueCursorWithoutRebinding() {
        val transport = StreamDocumentTransport()
        val lines = mutableListOf<String>()
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--android", "--json", "logs", "--follow", "--limit", "0"),
            printLine = lines::add, requestCommand = { error("desktop owner") },
            androidRequest = DesktopAndroidAdbClient(transport::execute)::request,
            streamPause = {}, streamActive = { transport.submissions < 2 }))

        assertEquals(2, transport.submissions)
        assertEquals(listOf(null, "owner"), transport.requests.map { it.controllerId })
        assertEquals(ControlValue.Text("0"), transport.requests[0].command.arguments["limit"])
        assertNull(transport.requests[0].command.arguments["after"])
        assertEquals(ControlValue.Text("100"), transport.requests[1].command.arguments["limit"])
        assertEquals(ControlValue.Text("tail-0"), transport.requests[1].command.arguments["after"])
        assertTrue(transport.requests.all { it.command.operation == ControlOperationId.LOGS })
        assertEquals(listOf(ControlCode.OK, ControlCode.OK, ControlCode.CANCELLED),
            lines.map(ControlDocumentCodec::decodeResult).map { it.code })
    }

    @Test fun documentTransportReplacementAndPostSubmitLossEndWatchWithoutRetryOrMutation() {
        for (failure in listOf("replacement", "lost")) {
            val transport = StreamDocumentTransport(failure)
            val lines = mutableListOf<String>()
            val exit = DesktopCli.handleArgs(arrayOf("--android", "--json", "status", "--watch"),
                printLine = lines::add, requestCommand = { error("desktop owner") },
                androidRequest = DesktopAndroidAdbClient(transport::execute)::request, streamPause = {},
                streamActive = { transport.submissions < 3 })

            // A provider's explicit stale-owner conflict is action failure (1);
            // loss after submission has unknown outcome (2). Both must terminate.
            assertEquals(if (failure == "replacement") 1 else 2, exit, failure)
            assertEquals(2, transport.submissions, failure)
            assertEquals(listOf(null, "owner"), transport.requests.map { it.controllerId }, failure)
            assertTrue(transport.requests.all { it.command.operation == ControlOperationId.STATUS }, failure)
            assertEquals(2, lines.size, failure)
            assertEquals(ControlCode.OK, ControlDocumentCodec.decodeResult(lines.first()).code, failure)
            assertEquals(if (failure == "replacement") ControlCode.CONFLICT else ControlCode.OUTCOME_UNKNOWN,
                ControlDocumentCodec.decodeResult(lines.last()).code, failure)
        }
    }

    @Test fun interruptingInFlightAndroidDocumentWatchCancelsWithoutRepollingOwner() {
        val transport = StreamDocumentTransport(interruptOnSubmission = 2)
        val lines = mutableListOf<String>()
        var exit: Int? = null
        val worker = Thread {
            exit = DesktopCli.handleArgs(arrayOf("--android", "--json", "status", "--watch"),
                printLine = lines::add, requestCommand = { error("desktop owner") },
                androidRequest = DesktopAndroidAdbClient(transport::execute)::request, streamPause = {})
        }
        worker.start()
        try {
            assertTrue(transport.interruptedSubmission.await(2, TimeUnit.SECONDS), "second read must be in flight")
            worker.interrupt()
            worker.join(2_000)
            assertFalse(worker.isAlive)
            assertEquals(130, exit)
            assertEquals(2, transport.submissions)
            assertTrue(transport.requests.all { it.command.operation == ControlOperationId.STATUS })
            assertEquals(listOf(ControlCode.OK, ControlCode.CANCELLED),
                lines.map(ControlDocumentCodec::decodeResult).map { it.code })
        } finally {
            worker.interrupt()
            worker.join(2_000)
        }
    }

    private class StreamDocumentTransport(
        private val failure: String? = null,
        private val interruptOnSubmission: Int? = null,
    ) {
        val requests = mutableListOf<ControlRequest>()
        var submissions = 0
        val interruptedSubmission = CountDownLatch(1)
        private val upload = ByteArrayOutputStream()
        private var output = byteArrayOf()
        private var currentId = ""

        fun execute(args: List<String>, input: ByteArray, timeout: Long): DesktopAdbProcessResult {
            assertTrue(timeout > 0)
            if (args == listOf("devices")) return response("List of devices attached\ntest\tdevice\n")
            assertEquals(listOf("-s", "test", "shell", "-T", "content"), args.take(5))
            if (args[5] == "write") {
                upload.write(input)
                return response("")
            }
            val method = args[9]
            return response(when (method) {
                "document-begin" -> {
                    upload.reset()
                    currentId = UUID.randomUUID().toString()
                    bundle("id" to currentId, "controllerId" to if (failure == "replacement" && submissions > 0) "replacement" else "owner", "chunkBytes" to "65536")
                }
                "document-seal" -> bundle("id" to currentId, "byteCount" to upload.size().toString(),
                    "sha256" to hash(upload.toByteArray()), "chunkBytes" to "65536")
                "document-submit" -> {
                    val request = ControlDocumentCodec.decodeRequest(upload.toString(Charsets.UTF_8))
                    requests += request
                    submissions++
                    if (submissions == interruptOnSubmission) {
                        interruptedSubmission.countDown()
                        Thread.sleep(Long.MAX_VALUE)
                    }
                    if (failure == "lost" && submissions == 2) throw java.io.IOException("synthetic device loss")
                    val owner = if (failure == "replacement" && submissions == 2) "replacement" else "owner"
                    val code = if (failure == "replacement" && submissions == 2) ControlCode.CONFLICT else ControlCode.OK
                    output = ControlDocumentCodec.encodeResult(ControlResult(owner, request.requestId, code, 7,
                        data = if (request.command.operation == ControlOperationId.LOGS) logData(submissions) else mapOf("running" to ControlValue.Null))).toByteArray()
                    bundle("state" to "complete")
                }
                "document-result" -> bundle("id" to OUTPUT, "byteCount" to output.size.toString(), "sha256" to hash(output), "chunkBytes" to "65536")
                "document-read" -> {
                    val parts = args.last().split(':')
                    val offset = parts[1].toInt(); val length = parts[2].toInt()
                    bundle("id" to OUTPUT, "offset" to offset.toString(),
                        "data" to Base64.getEncoder().encodeToString(output.copyOfRange(offset, offset + length)))
                }
                "document-discard" -> bundle("state" to "discarded")
                else -> error("Unexpected method $method")
            })
        }

        private fun logData(read: Int): Map<String, ControlValue> = if (read == 1) mapOf(
            "entries" to ControlValue.ArrayValue(emptyList()), "nextCursor" to ControlValue.Text("tail-0"), "gap" to ControlValue.BooleanValue(false)
        ) else mapOf(
            "entries" to ControlValue.ArrayValue(listOf(ControlValue.ObjectValue(mapOf("id" to ControlValue.Text("entry-1"),
                "createdAtEpochMillis" to ControlValue.IntegerValue(1), "message" to ControlValue.Text("same"))))),
            "nextCursor" to ControlValue.Text("entry-1"), "gap" to ControlValue.BooleanValue(false)
        )
    }

    private companion object {
        const val OUTPUT = "22222222-2222-4222-8222-222222222222"
        fun response(value: String) = DesktopAdbProcessResult(0, value.toByteArray(), byteArrayOf())
        fun bundle(vararg fields: Pair<String, String>) = "Result: Bundle[{" + fields.joinToString(", ") { "${it.first}=${it.second}" } + "}]"
        fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value).joinToString("") { "%02x".format(it) }
    }
}
