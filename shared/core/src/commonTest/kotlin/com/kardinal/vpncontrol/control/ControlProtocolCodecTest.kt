package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ControlProtocolCodecTest {
    private val request = ControlRequest(
        requestId = "request-1",
        controllerId = "controller-1",
        ifRevision = 7,
        command = ControlCommand(ControlOperationId.LOCATIONS_ADD, mapOf(
            "content" to ControlValue.Text("socks://secret@localhost:1080#東京 \"office\"\n"),
            "options" to ControlValue.ObjectValue(mapOf(
                "enabled" to ControlValue.BooleanValue(true),
                "count" to ControlValue.IntegerValue(Long.MAX_VALUE),
                "hours" to ControlValue.DecimalValue(1.5),
                "tags" to ControlValue.ArrayValue(listOf(ControlValue.Null, ControlValue.Text("русский"))),
            )),
        )),
    )

    @Test
    fun requestRoundTripPreservesContentAndTypes() {
        assertEquals(request, ControlProtocolCodec.decodeRequest(ControlProtocolCodec.encodeRequest(request)))
    }

    @Test
    fun resultRoundTripPreservesStructuredDataAndIdentity() {
        for (code in ControlCode.entries) {
            val result = ControlResult(
                controllerId = "controller-1", requestId = "request-1", code = code,
                configurationRevision = Long.MAX_VALUE, message = "safe",
                messageKey = "key", messageArgs = listOf("arg"),
                operationId = "operation-1", final = code != ControlCode.ACCEPTED,
                restartRequired = true, data = request.command.arguments, warnings = listOf("warning"),
            )
            assertEquals(result, ControlProtocolCodec.decodeResult(ControlProtocolCodec.encodeResult(result)))
        }
    }

    @Test
    fun unknownRequestFieldsAndWrongTypesFailClosed() {
        val frame = ControlProtocolCodec.encodeRequest(request)
        for (invalid in listOf(
            frame.replace("\"interactive\":false", "\"interactive\":\"false\""),
            frame.replace("\"ifRevision\":7", "\"ifRevision\":7.5"),
            frame.replace("\"ifRevision\":7", "\"ifRevision\":-1"),
            frame.replace("\"controllerId\":\"controller-1\"", "\"controllerId\":null"),
            frame.replace("\"asynchronous\":false", "\"asynchronous\":false,\"executeShell\":true"),
            frame.replace("\"operation\":\"locations.add\"", "\"operation\":false"),
            frame.replace("\"count\":9223372036854775807", "\"count\":9223372036854775808"),
        )) {
            assertEquals(ControlCode.INVALID_ARGUMENT, assertFailsWith<ControlProtocolException> {
                ControlProtocolCodec.decodeRequest(invalid)
            }.code)
        }
    }

    @Test
    fun duplicateKeysIncludingEscapedAliasesAreRejected() {
        val frame = ControlProtocolCodec.encodeRequest(request)
        for (invalid in listOf(
            frame.replace("\"interactive\":false", "\"interactive\":false,\"interactive\":true"),
            frame.replace("\"interactive\":false", "\"interactive\":false,\"interact\\u0069ve\":true"),
            frame.replace("\"count\":9223372036854775807", "\"count\":1,\"count\":2"),
        )) assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeRequest(invalid) }
    }

    @Test
    fun wrongVersionIsNotReportedAsMissingController() {
        val frame = ControlProtocolCodec.encodeRequest(request).replace("\"schemaVersion\":1", "\"schemaVersion\":2")
        val error = assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeRequest(frame) }
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, error.code)
        assertEquals(2, error.code.exitCode)
    }

    @Test
    fun malformedFramesHaveNoSecretInExceptionOrCause() {
        for (frame in listOf("{\"secret\":TOP_SECRET}", "[", "null", "{\"key\":\"TOP_SECRET", "}")) {
            val error = assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeRequest(frame) }
            assertEquals("INVALID_ARGUMENT", error.message)
            assertEquals(null, error.cause)
        }
    }

    @Test
    fun boundsApplyToUtf8BytesAndNesting() {
        val large = request.copy(command = ControlCommand(ControlOperationId.LOCATIONS_ADD, mapOf(
            "content" to ControlValue.Text("東".repeat(ControlProtocolCodec.MAX_FRAME_BYTES / 2)),
        )))
        assertFailsWith<ControlProtocolException> { ControlProtocolCodec.encodeRequest(large) }
        assertFailsWith<ControlProtocolException> {
            ControlProtocolCodec.decodeRequest("{\"value\":" + "[".repeat(1000) + "]".repeat(1000) + "}")
        }
        // Brackets and escaped quotes inside strings are content, not nesting.
        val quoted = request.copy(command = ControlCommand(ControlOperationId.LOCATIONS_ADD, mapOf(
            "content" to ControlValue.Text("[\\\"{".repeat(100)),
        )))
        assertEquals(quoted, ControlProtocolCodec.decodeRequest(ControlProtocolCodec.encodeRequest(quoted)))
    }

    @Test
    fun successFlagCannotContradictCode() {
        val frame = ControlProtocolCodec.encodeResult(ControlResult(null, "id", ControlCode.RUNTIME_FAILED, 0))
        assertFailsWith<ControlProtocolException> {
            ControlProtocolCodec.decodeResult(frame.replace("\"ok\":false", "\"ok\":true"))
        }
    }

    @Test
    fun incidentalLoggingDoesNotPrintPrivateArguments() {
        assertFalse(request.toString().contains("secret"))
        assertFalse(request.command.toString().contains("secret"))
        assertFalse(request.command.arguments.toString().contains("secret"))
        assertTrue(ControlProtocolCodec.encodeRequest(request).contains("secret"))
    }
}
