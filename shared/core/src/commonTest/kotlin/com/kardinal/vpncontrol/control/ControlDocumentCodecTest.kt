package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlDocumentCodecTest {
    @Test fun streamedResultsMatchEveryCanonicalFieldAndDepthBoundary() {
        val units = buildString { for (code in 0..65535) append(code.toChar()) }
        for (code in listOf(ControlCode.OK, ControlCode.OUTCOME_UNKNOWN, ControlCode.ACCEPTED)) {
            val result = ControlResult(null, "request", code, 7, message = units, messageKey = "key",
                messageArgs = listOf("東京", "\uD800"), final = code != ControlCode.ACCEPTED,
                operationId = "operation", restartRequired = true,
                data = mapOf("value" to ControlValue.ArrayValue(listOf(ControlValue.DecimalValue(-0.0), ControlValue.Null))),
                warnings = listOf("warning"))
            assertEquals(ControlDocumentCodec.encodeResult(result), buildString { ControlDocumentCodec.writeResult(result, this) })
        }
        for (depth in 28..34) {
            var value: ControlValue = ControlValue.Text("x")
            repeat(depth) { value = ControlValue.ArrayValue(listOf(value)) }
            val result = ControlResult("owner", "request", ControlCode.OK, 0, data = mapOf("v" to value))
            val old = runCatching { ControlDocumentCodec.encodeResult(result) }
            val streamed = runCatching { buildString { ControlDocumentCodec.writeResult(result, this) } }
            assertEquals(old.isSuccess, streamed.isSuccess, "depth=$depth")
            if (old.isSuccess) assertEquals(old.getOrThrow(), streamed.getOrThrow())
        }
    }
    @Test fun streamedValuesMatchCanonicalCharactersAndNestingRules() {
        val units = buildString { for (code in 0..65535) append(code.toChar()) }
        val values = linkedMapOf("z" to ControlValue.Text(units), "a\n" to ControlValue.ArrayValue(listOf(
            ControlValue.DecimalValue(-0.0), ControlValue.DecimalValue(Double.MAX_VALUE),
            ControlValue.ObjectValue(mapOf("\\\"" to ControlValue.BooleanValue(false))), ControlValue.Null)))
        assertEquals(ControlDocumentCodec.encodeValues(values), buildString { ControlDocumentCodec.writeValues(values, this) })
        for (depth in 29..34) {
            var value: ControlValue = ControlValue.Text("x")
            repeat(depth) { value = ControlValue.ArrayValue(listOf(value)) }
            val nested = mapOf("v" to value)
            val old = runCatching { ControlDocumentCodec.encodeValues(nested) }
            val streamed = runCatching { buildString { ControlDocumentCodec.writeValues(nested, this) } }
            assertEquals(old.isSuccess, streamed.isSuccess, "depth=$depth")
            if (old.isSuccess) assertEquals(old.getOrThrow(), streamed.getOrThrow())
        }
    }
    private fun values(repeats: Int) = mapOf("content" to ControlValue.Text("東\\\"\n".repeat(repeats)))

    @Test fun domainDocumentsDoNotInheritTransportFrameLimits() {
        val padding = " ".repeat(ControlProtocolCodec.MAX_FRAME_BYTES + 1)
        val settings = ControlSettingsLogic.parseRequestArguments(ControlOperationId.SETTINGS_APPLY,
            mapOf("input" to ControlValue.Text("$padding{\"mode\":\"proxy-only\"}"))).getOrThrow()
        assertEquals(mapOf("mode" to ControlValue.Text("proxy-only")), settings)
        assertEquals(ControlValue.BooleanValue(true), ControlSettingsLogic.parseTerminalValue("ssh.enabled", "$padding true").getOrThrow())
        val rules = RoutingRules(directDomainSuffixes = (0 until 70_000).map { "domain-$it.example.test" })
        val inspected = ControlConfigurationInspection.read(com.kardinal.vpncontrol.MainUiState(routingRules = rules),
            ControlCommand(ControlOperationId.ROUTING_SHOW), 0).getOrThrow()
        val routing = (inspected.getValue("routing") as ControlValue.ObjectValue).values
        val document = ControlDocumentCodec.encodeValues(routing)
        assertTrue(document.encodeToByteArray().size > ControlProtocolCodec.MAX_FRAME_BYTES)
        assertEquals(rules, com.kardinal.vpncontrol.data.RoutingRulesTransfer.import(document))
    }

    @Test fun largeLogicalDocumentsRoundTripWhileWireFramesRemainBounded() {
        for (size in listOf(250_000, 1_600_000)) {
            val data = values(size)
            val request = ControlRequest("request", ControlCommand(ControlOperationId.LOCATIONS_IMPORT, data),
                controllerId = "owner")
            val result = ControlResult("owner", "request", ControlCode.OK, 4, data = data)
            val requestText = ControlDocumentCodec.encodeRequest(request)
            val resultText = ControlDocumentCodec.encodeResult(result)
            val valuesText = ControlDocumentCodec.encodeValues(data)
            assertTrue(requestText.encodeToByteArray().size > ControlProtocolCodec.MAX_FRAME_BYTES)
            assertEquals(request, ControlDocumentCodec.decodeRequest(requestText))
            assertEquals(result, ControlDocumentCodec.decodeResult(resultText))
            assertEquals(data, ControlDocumentCodec.decodeValues(valuesText))
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.encodeRequest(request) }
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeRequest(requestText) }
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.encodeResult(result) }
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeResult(resultText) }
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.encodeValues(data) }
            assertFailsWith<ControlProtocolException> { ControlProtocolCodec.decodeValues(valuesText) }
        }
    }

    @Test fun snapshotsSupportOneLargeResultAndAccumulatedSmallResults() {
        for ((count, size) in listOf(1 to 250_000, 64 to 4_000)) {
            val operations = (0 until count).map { i ->
                val result = ControlResult("owner", "request-$i", ControlCode.OK, 4,
                    operationId = "operation-$i", data = values(size))
                ControlOperation("operation-$i", "request-$i", ControlOperationId.LOCATIONS_IMPORT,
                    ControlOperationPhase.SUCCEEDED, false, result = result)
            }
            val snapshot = ControlSnapshot("owner", 4, null, null, AppMode.VPN, null,
                null, null, false, operations, false)
            val document = ControlSnapshotCodec.encodeDocument(snapshot)
            assertTrue(document.encodeToByteArray().size > ControlProtocolCodec.MAX_FRAME_BYTES)
            assertEquals(snapshot, ControlSnapshotCodec.decodeDocument(document))
            assertFailsWith<ControlProtocolException> { ControlSnapshotCodec.encode(snapshot) }
            assertFailsWith<ControlProtocolException> { ControlSnapshotCodec.decode(document) }
            assertFailsWith<ControlProtocolException> {
                ControlSnapshotCodec.decodeDocument(document.replaceFirst("\"requestId\":\"request-0\"", "\"requestId\":\"other\""))
            }
        }
    }

    @Test fun largeDocumentsRetainValidationAndSanitizedErrors() {
        val padding = "x".repeat(ControlProtocolCodec.MAX_FRAME_BYTES + 1)
        for (invalid in listOf(
            "{\"padding\":\"$padding\",\"key\":1,\"k\\u0065y\":2}",
            "{\"padding\":\"$padding\",\"deep\":" + "[".repeat(40) + "0" + "]".repeat(40) + "}",
            "{\"padding\":\"$padding\",\"secret\":TOP_SECRET}",
        )) {
            val error = assertFailsWith<ControlProtocolException> { ControlDocumentCodec.decodeValues(invalid) }
            assertEquals(ControlCode.INVALID_ARGUMENT, error.code)
            assertNull(error.cause)
            assertFalse(error.message.orEmpty().contains("TOP_SECRET"))
        }
        val result = ControlDocumentCodec.encodeResult(ControlResult("owner", "request", ControlCode.OK, 4,
            data = mapOf("padding" to ControlValue.Text(padding))))
        assertFailsWith<ControlProtocolException> { ControlDocumentCodec.decodeResult(result.replace("\"ok\":true", "\"ok\":false")) }
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, assertFailsWith<ControlProtocolException> {
            ControlDocumentCodec.decodeResult(result.replace("\"schemaVersion\":1", "\"schemaVersion\":2"))
        }.code)
    }
}
