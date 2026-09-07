package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlCharacterRequestTest {
    private fun source(value: String): ControlCharacterSource {
        var index = 0
        return ControlCharacterSource { if (index == value.length) -1 else value[index++].code }
    }
    private fun document(value: String) = """{"schemaVersion":1,"requestId":"r","interactive":false,"asynchronous":false,"command":{"operation":"locations.import","arguments":{"input":$value}}}"""

    @Test fun streamingMatchesExistingStringDecoderForStrictnessAndScalarRules() {
        val values = listOf("null", "true", "false", "0", "-0", "01", "1.", ".1", "1e3", "1e999",
            "9223372036854775807", "9223372036854775808", "NaN", "TOP_SECRET", "\"東京😀\"",
            "\"a\\n\\t\\b\\f\\r\\/\\\\\\\"b\"", "\"\\uD83D\\uDE00\"", "\"\\uD800\"", "\"\\uDC00\"",
            "\"\uD800\"", "\"raw\nline\"", "\"\\u12xx\"", "\"\\x\"", "[1,true,\"x\"]",
            "{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}", "[1,]", "{\"x\":1,}",
            "\"\\u٠٠٤١\"", "\"\\u００４１\"", "\"\\uFFff\"", "\"\\u123\"",
            "+1", "-01", "1E+02", "1e", "--1", "0x1", "TRUE", "Null")
        val documents = values.map(::document) + (0..31).map { document("\"a${it.toChar()}b\"") } + listOf(
            document("0") + " trailing", document("0").replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            document("0").replace("\"requestId\":\"r\"", "\"requestId\":\"r\",\"requestId\":\"s\""),
            document("0").replace("\"interactive\":false", "\"interactive\":\"false\""),
            document("0").replace("\"arguments\"", "\"other\""),
            document("0").replace("\"requestId\"", "requestId"),
            document("[".repeat(32) + "0" + "]".repeat(32)),
        )
        for ((index, text) in documents.withIndex()) {
            val previous = runCatching { ControlDocumentCodec.decodeRequest(text) }
            val streamed = runCatching { ControlDocumentCodec.decodeRequest(source(text)) }
            if (previous.isSuccess) {
                assertTrue(streamed.isSuccess, "case $index")
                assertEquals(previous.getOrThrow(), streamed.getOrThrow(), "case $index")
            }
            else {
                val old = previous.exceptionOrNull() as ControlProtocolException
                val new = streamed.exceptionOrNull() as? ControlProtocolException
                assertEquals(old.code, new?.code, "case $index")
                assertNull(new?.cause)
                assertFalse(new?.message.orEmpty().contains("TOP_SECRET"))
            }
        }
    }

    @Test fun generatesElevenMiBInputWithoutAnOuterDocumentString() {
        val size = 11 * 1024 * 1024 + 17
        val empty = document("\"\"")
        val split = empty.indexOf("\"input\":\"\"") + "\"input\":\"".length
        val prefix = empty.substring(0, split)
        val suffix = empty.substring(split)
        var position = 0
        val decoded = ControlDocumentCodec.decodeRequest(ControlCharacterSource {
            val index = position++
            when {
                index < prefix.length -> prefix[index].code
                index < prefix.length + size -> 'x'.code
                index < prefix.length + size + suffix.length -> suffix[index - prefix.length - size].code
                else -> -1
            }
        })
        val content = (decoded.command.arguments.getValue("input") as ControlValue.Text).value
        assertEquals(size, content.length)
        assertEquals('x', content.first())
        assertEquals('x', content.last())
    }

    @Test fun sourceFailuresPropagateWithoutBeingReportedAsInvalidPrivateInput() {
        class SourceFailure : Exception()
        val failure = SourceFailure()
        assertSame(failure, assertFailsWith<SourceFailure> {
            ControlDocumentCodec.decodeRequest(ControlCharacterSource { throw failure })
        })
        assertEquals(ControlCode.INVALID_ARGUMENT, assertFailsWith<ControlProtocolException> {
            ControlDocumentCodec.decodeRequest(ControlCharacterSource { 65536 })
        }.code)
    }

    @Test fun compactChunksPreserveEveryUtf16UnitAcrossGrowthAndChunkBoundaries() {
        val units = buildString {
            repeat(8191) { append('a') }
            append('\uD800'); append('\uDC00'); append('\uFFFF')
            for (code in 0..65535) append(code.toChar())
            repeat(8193) { append('\u00FF') }
            append('\uD800')
        }
        val request = ControlRequest("units", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
            mapOf("input" to ControlValue.Text(units))))
        val encoded = ControlDocumentCodec.encodeRequest(request)
        assertEquals(request, ControlDocumentCodec.decodeRequest(source(encoded)))
    }
}
