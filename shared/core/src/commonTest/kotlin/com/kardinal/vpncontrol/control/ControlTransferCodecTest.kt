package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlTransferCodecTest {
    private val id = "00000000-0000-4000-8000-000000000001"
    @Test fun boundedChunkRoundTripsWithoutLoggingContent() {
        val bytes = ByteArray(ControlTransferLimits.CHUNK_BYTES) { (it % 256).toByte() }
        val encoded = ControlTransferCodec.encode(ControlTransferCommand.Append(id, 7, bytes))
        assertTrue(encoded.encodeToByteArray().size < ControlTransferLimits.FRAME_BYTES)
        val decoded = assertIs<ControlTransferCommand.Append>(ControlTransferCodec.decode(encoded))
        assertEquals(7L, decoded.offset)
        assertContentEquals(bytes, decoded.bytes)
        assertFalse(decoded.toString().contains(id))
        for (content in listOf(bytes, byteArrayOf())) {
            val response = ControlTransferCodec.decodeChunk(ControlTransferCodec.encodeChunk(ControlTransferChunk(id, 9, content)))
            assertEquals(9L, response.offset)
            assertContentEquals(content, response.bytes)
        }
    }
    @Test fun rejectsUnknownDuplicateUnsafeAndOversizeFields() {
        for (frame in listOf(
            "{\"action\":\"discard\",\"id\":\"$id\",\"path\":\"/tmp/secret\"}",
            "{\"action\":\"discard\",\"id\":\"$id\",\"id\":\"$id\"}",
            "{\"action\":\"discard\",\"id\":\"../secret\"}",
            "{\"action\":\"read\",\"id\":\"$id\",\"offset\":-1,\"length\":1}",
            "{\"action\":\"read\",\"id\":\"$id\",\"offset\":0,\"length\":65537}",
            " ".repeat(ControlTransferLimits.FRAME_BYTES + 1),
        )) assertFailsWith<ControlProtocolException> { ControlTransferCodec.decode(frame) }
    }
    @Test fun metadataCommandsAndManifestRoundTrip() {
        for (command in listOf(ControlTransferCommand.Begin("request"), ControlTransferCommand.Discard(id),
            ControlTransferCommand.Read(id, Long.MAX_VALUE, 0), ControlTransferCommand.Seal(id, Long.MAX_VALUE, "a".repeat(64)))) {
            assertEquals(command, ControlTransferCodec.decode(ControlTransferCodec.encode(command)))
        }
        val manifest = ControlTransferManifest(id, Long.MAX_VALUE, "a".repeat(64))
        assertEquals(manifest, ControlTransferCodec.decodeManifest(ControlTransferCodec.encodeManifest(manifest)))
    }
}
