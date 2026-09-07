package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidControlDocumentResponseTest {
    @Test fun streamedTimestampMatchesSharedExporterAtMillisecondBoundaries() = runBlocking {
        for (millis in listOf(-1001L, -1L, 0L, 1L, 10L, 100L, 999L, 1788719400123L)) {
            val reader = AndroidControlReader("owner", { PersistedState() }, clockMillis = { millis })
            val request = ControlRequest("timestamp", ControlCommand(ControlOperationId.ROUTING_EXPORT))
            val expected = reader.read(request)
            val actual = reader.documentResponse(ControlDocumentCodec.encodeRequest(request).byteInputStream(), "transport")
            assertEquals("timestamp millis=$millis", ControlDocumentCodec.encodeResult(expected), buildString { actual.writeTo(this) })
        }
    }

    @Test fun streamingExportIsByteEquivalentAndCapturesOneCommittedSnapshot() = runBlocking {
        var state = PersistedState(routingRules = RoutingRules(directDomainSuffixes = listOf("東京.test", "one.test")))
        val reader = AndroidControlReader("owner", { state }, clockMillis = { 0 },
            committedSnapshot = { ControlCommitted("owner", 8, state) }, pendingRestart = { false })
        val request = ControlRequest("export", ControlCommand(ControlOperationId.ROUTING_EXPORT), controllerId = "owner")
        val expected = reader.read(request)
        val actual = reader.documentResponse(ControlDocumentCodec.encodeRequest(request).byteInputStream(), "transport")
        state = state.copy(routingRules = RoutingRules(directDomainSuffixes = listOf("changed.test")))
        val encoded = buildString { actual.writeTo(this) }
        assertEquals(ControlDocumentCodec.encodeResult(expected), encoded)
        assertEquals(8L, ControlDocumentCodec.decodeResult(encoded).configurationRevision)
        assertFalse(encoded.contains("changed.test"))
    }

    @Test fun invalidExportArgumentsNeverCreateSuccessContent() = runBlocking {
        val reader = AndroidControlReader("owner", { PersistedState() })
        val request = ControlRequest("invalid", ControlCommand(ControlOperationId.ROUTING_EXPORT,
            mapOf("unexpected" to ControlValue.Text("private"))))
        val response = reader.documentResponse(ControlDocumentCodec.encodeRequest(request).byteInputStream(), "transport")
        val decoded = ControlDocumentCodec.decodeResult(buildString { response.writeTo(this) })
        assertEquals(ControlCode.INVALID_ARGUMENT, decoded.code)
        assertFalse("content" in decoded.data)
    }
}
