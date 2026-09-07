package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class AndroidControlInputSpoolTest {
    @Test fun privateUtf16SpoolPreservesEveryUnitAndCanonicalFingerprint() {
        val directory = Files.createTempDirectory("control-input-units")
        try {
            val text = buildString { for (unit in 0..65535) append(unit.toChar()) }
            AndroidControlInputSpool(AndroidControlTransferSpool.create(directory)).use { input ->
                input.append(text); input.seal()
                assertEquals(text, input.materialize())
                assertEquals(androidControlRequestFingerprint(mapOf("input" to ControlValue.Text(text)), 7, false, false),
                    androidControlInputFingerprint(input.source(), 7))
                assertEquals(text.length.toLong(), input.length)
                assertFalse(input.toString().contains(text.take(10)))
                assertEquals(0L, Files.list(directory).use { it.count() })
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun fallbackAndInvalidEnvelopeAlwaysClosePrivateInput() = kotlinx.coroutines.test.runTest {
        var closes = 0
        fun spool(): AndroidControlInputSpool = AndroidControlInputSpool(object : ControlTransferSpool {
            private val bytes = java.io.ByteArrayOutputStream()
            override fun append(bytes: ByteArray) { this.bytes.write(bytes) }
            override fun read(offset: Long, length: Int) = bytes.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length)
            override fun sha256() = error("not used")
            override fun erase() { closes++ }
        })
        val payload = "other command \uD800 東京"
        val reader = AndroidControlReader("owner", { PersistedState() }, inputSpool = ::spool,
            settingsWrite = { request ->
                assertEquals(ControlValue.Text(payload), request.command.arguments["input"])
                ControlResult("owner", request.requestId, ControlCode.OK, 0)
            })
        val request = ControlRequest("fallback", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
            mapOf("input" to ControlValue.Text(payload))), controllerId = "owner")
        val document = ControlDocumentCodec.encodeRequest(request).toByteArray(Charsets.UTF_8)
        // UTF8 replacement is the same transport behavior before and after extraction.
        val validPayload = payload.replace('\uD800', '?')
        val safeReader = AndroidControlReader("owner", { PersistedState() }, inputSpool = ::spool,
            settingsWrite = { actual ->
                assertEquals(ControlValue.Text(validPayload), actual.command.arguments["input"])
                ControlResult("owner", actual.requestId, ControlCode.OK, 0)
            })
        assertEquals(ControlCode.OK, safeReader.documentResult(document.inputStream(), "transfer").code)
        assertEquals(1, closes)
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.documentResult("{\"command\":{\"arguments\":{\"input\":\"abc\"}},".byteInputStream(), "bad").code)
        assertEquals(2, closes)
    }
}
