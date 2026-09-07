package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlExternalInputRequestTest {
    @Test fun sourceAndSinkFailuresEscapeWithoutBecomingMalformedInput() {
        class StorageFailure : Exception()
        val failure = StorageFailure()
        val sink = object : Appendable {
            override fun append(value: Char): Appendable = throw failure
            override fun append(value: CharSequence?): Appendable = throw failure
            override fun append(value: CharSequence?, start: Int, end: Int): Appendable = throw failure
        }
        assertSame(failure, assertFailsWith<StorageFailure> {
            ControlDocumentCodec.decodeRequestWithExternalInput(source(document("""{"input":"x"}""")), sink)
        })
        assertSame(failure, assertFailsWith<StorageFailure> {
            ControlDocumentCodec.decodeRequestWithExternalInput(ControlCharacterSource { throw failure }, StringBuilder())
        })
        assertSame(failure, assertFailsWith<StorageFailure> {
            ControlDocumentCodec.writeQuotedText(ControlCharacterSource { throw failure }, StringBuilder())
        })
    }
    private fun source(text: String): ControlCharacterSource {
        var index = 0
        return ControlCharacterSource { if (index == text.length) -1 else text[index++].code }
    }
    private fun document(arguments: String) = """{"schemaVersion":1,"requestId":"r","interactive":false,"asynchronous":false,"command":{"arguments":$arguments,"operation":"routing.import"}}"""

    @Test fun onlyExactStringInputIsExternalizedAndAllOtherValuesRemainIntact() {
        for (input in listOf("\"東京\\n\\uD800😀\"", "42", "null", "true", "[\"x\"]", "{\"input\":\"nested\"}")) {
            val encoded = document("""{"nested":{"input":"keep"},"input":$input}""")
            val expected = ControlDocumentCodec.decodeRequest(encoded)
            val output = StringBuilder()
            val decoded = ControlDocumentCodec.decodeRequestWithExternalInput(source(encoded), output)
            val original = expected.command.arguments["input"]
            assertEquals(original is ControlValue.Text, decoded.inputExtracted)
            if (original is ControlValue.Text) {
                assertFalse(decoded.request.command.arguments.containsKey("input"))
                assertEquals(original.value, output.toString())
                assertEquals(expected, decoded.request.copy(command = decoded.request.command.copy(
                    arguments = decoded.request.command.arguments + ("input" to ControlValue.Text(output.toString())))))
            } else {
                assertEquals(expected, decoded.request)
                assertEquals("", output.toString())
            }
        }
    }

    @Test fun extractionDoesNotRelaxDuplicateDepthUnknownFieldOrMalformedValidation() {
        val valid = document("""{"input":"secret"}""")
        val invalid = listOf(
            document("""{"input":"secret","input":"again"}"""),
            document("""{"input":"secret","\u0069nput":null}"""),
            valid + " trailing", valid.replace("\"command\":", "\"unknown\":0,\"command\":"),
            document("""{"input":"\uXX00"}"""), document("""{"input":"unterminated}"""),
            document("""{"input":"ok","nested":${"[".repeat(33)}0${"]".repeat(33)}}"""),
        )
        for (text in invalid) {
            val prior = assertFailsWith<ControlProtocolException> { ControlDocumentCodec.decodeRequest(source(text)) }
            val extracted = assertFailsWith<ControlProtocolException> {
                ControlDocumentCodec.decodeRequestWithExternalInput(source(text), StringBuilder())
            }
            assertEquals(prior.code, extracted.code)
            assertNull(extracted.cause)
        }
    }

    @Test fun quotedCharacterStreamExactlyMatchesCanonicalTextEscapingForEveryUtf16Unit() {
        val text = buildString { for (unit in 0..65535) append(unit.toChar()) }
        val expected = ControlDocumentCodec.encodeValues(mapOf("x" to ControlValue.Text(text)))
            .removePrefix("{\"x\":").removeSuffix("}")
        val output = StringBuilder()
        ControlDocumentCodec.writeQuotedText(source(text), output)
        assertEquals(expected, output.toString())
    }

    @Test fun largeInputIsDeliveredIncrementallyWithoutRetainingItInTheRequest() {
        val empty = document("""{"input":""}""")
        val start = empty.indexOf("\"input\":\"") + "\"input\":\"".length
        val prefix = empty.take(start)
        val suffix = empty.substring(start)
        val length = 11 * 1024 * 1024 + 17
        var index = 0
        var received = 0
        val sink = object : Appendable {
            override fun append(value: Char): Appendable { if (value != 'x') error("Unexpected unit"); received++; return this }
            override fun append(value: CharSequence?): Appendable = error("Expected incremental characters")
            override fun append(value: CharSequence?, start: Int, end: Int): Appendable = error("Expected incremental characters")
        }
        val decoded = ControlDocumentCodec.decodeRequestWithExternalInput(ControlCharacterSource {
            val position = index++
            when {
                position < prefix.length -> prefix[position].code
                position < prefix.length + length -> 'x'.code
                position < prefix.length + length + suffix.length -> suffix[position - prefix.length - length].code
                else -> -1
            }
        }, sink)
        assertTrue(decoded.inputExtracted)
        assertTrue(decoded.request.command.arguments.isEmpty())
        assertEquals(length, received)
    }
}
