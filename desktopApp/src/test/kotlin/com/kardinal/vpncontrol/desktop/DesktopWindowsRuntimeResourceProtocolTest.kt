package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.*

class DesktopWindowsRuntimeResourceProtocolTest {
    @Test fun capturedOwnerScopeAndDestinationsRemainBoundAcrossOrderingAndChunkBoundaries() {
        val fixture = fixture()
        val output = ByteArrayOutputStream()
        DesktopWindowsRuntimeResourceProtocol.writePreparation(fixture.first, fixture.second.reversed()) { bytes, offset, count ->
            assertTrue(count in 1..65536)
            output.write(bytes, offset, count)
        }
        val reader = ByteBuffer.wrap(output.toByteArray()).order(ByteOrder.LITTLE_ENDIAN)
        fun text(): String = ByteArray(reader.int).also { reader.get(it) }.decodeToString(throwOnInvalidSequence = true)
        assertEquals(1, reader.int)
        assertEquals(JOB, text())
        assertEquals(SCOPE, text())
        assertEquals(CONTROLLER, text())
        assertEquals(123L, reader.long)
        assertEquals(456L, reader.long)
        assertEquals(SID, text())
        assertEquals("C:\\workspace\\.scope", text())
        assertEquals("1".repeat(24), text())
        assertEquals("2".repeat(24), text())
        assertEquals(71L, reader.long)
        assertEquals("3".repeat(64), text())
        assertEquals(2, reader.int)
        for (entry in fixture.second) {
            assertEquals(entry.id, text())
            assertEquals(entry.kind.name, text())
        }
        for (entry in fixture.second) {
            assertEquals(entry.destination.path, text())
            assertEquals(entry.destination.parentIdentity, text())
        }
        assertFalse(reader.hasRemaining())
        assertTrue(output.size() > 65536)
    }

    @Test fun foreignMissingDuplicatedOrChangedResourcesFailBeforeAnyBytesAreSent() {
        val (job, resources) = fixture()
        val invalid = listOf(resources.drop(1), resources + resources.first(),
            resources.map { DesktopWindowsRuntimeResource(it.id, DesktopWindowsRuntimeResourceKind.OUTPUT, it.destination) },
            listOf(DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000099", resources[0].kind,
                resources[0].destination), resources[1]))
        for (candidate in invalid) {
            var writes = 0
            assertFailsWith<IllegalArgumentException> {
                DesktopWindowsRuntimeResourceProtocol.writePreparation(job, candidate) { _, _, _ -> writes++ }
            }
            assertEquals(0, writes)
        }
    }

    @Test fun malformedTextCannotSilentlyChangeAnAdmittedDestination() {
        val (job, resources) = fixture()
        val invalid = resources.map { DesktopWindowsRuntimeResource(it.id, it.kind,
            DesktopWindowsResourceDestination("C:\\bad\uD800", it.destination.parentIdentity)) }
        assertFailsWith<java.nio.charset.CharacterCodingException> {
            DesktopWindowsRuntimeResourceProtocol.writePreparation(job, invalid) { _, _, _ -> }
        }
    }

    @Test fun terminalEnvelopeFollowsNonemptyFinalLog() {
        val output = terminalStatusBytes()
        val log = "final-log".encodeToByteArray()
        var offset = 0
        val status = DesktopWindowsRuntimeResourceProtocol.readStatus(mutable = true) { count ->
            check(count >= 0 && offset + count <= output.size)
            output.copyOfRange(offset, offset + count).also { offset += count }
        }
        assertFalse(status.running)
        assertContentEquals(log, status.log)
        assertEquals(JOB, assertNotNull(status.resourceReconciliation).jobId)
        assertEquals(output.size, offset)
    }

    @Test fun truncatedOrInvalidTerminalEnvelopeIsRejectedBeforeReconciliation() {
        fun decode(bytes: ByteArray) {
            var offset = 0
            DesktopWindowsRuntimeResourceProtocol.readStatus(mutable = true) { count ->
                check(count >= 0 && offset + count <= bytes.size)
                bytes.copyOfRange(offset, offset + count).also { offset += count }
            }
        }
        assertFailsWith<IllegalStateException> { decode(terminalStatusBytes().dropLast(1).toByteArray()) }
        assertFailsWith<IllegalStateException> { decode(terminalStatusBytes(kind = 9)) }
    }

    companion object {
        private const val JOB = "00000000-0000-0000-0000-000000000031"
        private const val SCOPE = "00000000-0000-0000-0000-000000000032"
        private const val CONTROLLER = "00000000-0000-0000-0000-000000000033"
        private const val SID = "S-1-5-21-1-2-3-1001"
        private fun terminalStatusBytes(kind: Int = 0): ByteArray {
            val output = ByteArrayOutputStream()
            fun integer(value: Int) { output.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()) }
            fun text(value: String) { val bytes = value.encodeToByteArray(); integer(bytes.size); output.write(bytes) }
            val log = "final-log".encodeToByteArray()
            output.write(0); integer(log.size); output.write(log)
            integer(1); text(JOB); integer(1); text("00000000-0000-0000-0000-000000000041")
            output.write(kind); output.write(1); output.write(0); output.write(1)
            return output.toByteArray()
        }
        internal fun fixture(): Pair<DesktopWindowsRuntimeResourceJob, List<DesktopWindowsRuntimeResource>> {
            val scope = DesktopWindowsRuntimeResourceScope(SCOPE, CONTROLLER,
                DesktopWindowsResourceScopeRecord("C:\\workspace\\.scope", "1".repeat(24), "2".repeat(24), 71, "3".repeat(64)))
            val resources = listOf(
                DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000041", DesktopWindowsRuntimeResourceKind.CACHE,
                    DesktopWindowsResourceDestination("C:\\workspace\\cache.db", "4".repeat(24))),
                DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000042", DesktopWindowsRuntimeResourceKind.OUTPUT,
                    DesktopWindowsResourceDestination("C:\\" + "漢".repeat(32750), "5".repeat(24))),
            )
            return DesktopWindowsRuntimeResourceJob(JOB, scope,
                resources.map { DesktopWindowsRuntimeResourceEntry(it.id, it.kind) },
                DesktopWindowsRuntimeResourceNativeOwner(123, 456, SID)) to resources
        }
    }
}
