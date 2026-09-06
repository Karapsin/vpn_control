package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class ControlTransferStoreTest {
    private val binding = ControlTransferBinding("owner", "uid:1", ControlTransferPurpose.LOCATIONS_INPUT)
    private class MemorySpool : ControlTransferSpool {
        var bytes = byteArrayOf()
        var erased = false
        var fail = false
        override fun append(bytes: ByteArray) { check(!fail); this.bytes += bytes }
        override fun read(offset: Long, length: Int) = bytes.copyOfRange(offset.toInt(), offset.toInt() + length)
        override fun sha256() = "a".repeat(64)
        override fun erase() { erased = true; bytes.fill(0); bytes = byteArrayOf() }
    }
    private class Fixture {
        var now = 0L
        var sequence = 0
        val spools = mutableListOf<MemorySpool>()
        val store = ControlTransferStore("owner", { MemorySpool().also(spools::add) },
            { "00000000-0000-4000-8000-${(++sequence).toString().padStart(12, '0')}" }, { now }, idleMillis = 100)
    }
    @Test fun exactRetriesAndSealingRemainImmutable() = runTest {
        val f = Fixture()
        val id = f.store.begin(binding, "request").id
        assertEquals(id, f.store.begin(binding, "request").id)
        f.store.append(binding, id, 0, "abc".encodeToByteArray())
        f.store.append(binding, id, 0, "abc".encodeToByteArray())
        assertFailsWith<ControlProtocolException> { f.store.append(binding, id, 1, "XX".encodeToByteArray()) }
        assertFailsWith<ControlProtocolException> { f.store.seal(binding, id, 3, "b".repeat(64)) }
        val sealed = f.store.seal(binding, id, 3, "a".repeat(64))
        assertEquals(3L, sealed.byteCount)
        assertEquals(sealed, f.store.seal(binding, id, 3, "a".repeat(64)))
        assertFailsWith<ControlProtocolException> { f.store.append(binding, id, 3, byteArrayOf(1)) }
        assertContentEquals("abc".encodeToByteArray(), f.store.read(binding, id, 0, 3))
    }
    @Test fun wrongBindingsAndOffsetsNeverTouchSpool() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        for (wrong in listOf(binding.copy(ownerId = "other"), binding.copy(principal = "uid:2"),
            binding.copy(purpose = ControlTransferPurpose.ROUTING_INPUT))) {
            assertFailsWith<ControlProtocolException> { f.store.append(wrong, id, 0, byteArrayOf(65)) }
            assertFailsWith<ControlProtocolException> { f.store.discard(wrong, id) }
        }
        assertFailsWith<ControlProtocolException> { f.store.append(binding, id, Long.MAX_VALUE, byteArrayOf(65)) }
        assertTrue(f.spools.single().bytes.isEmpty())
    }
    @Test fun utf8AcrossChunksAndTruncationAreStrict() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        val emoji = "😀".encodeToByteArray()
        f.store.append(binding, id, 0, emoji.copyOfRange(0, 2))
        assertFailsWith<ControlProtocolException> { f.store.seal(binding, id, 2, "a".repeat(64)) }
        assertFailsWith<ControlProtocolException> { f.store.append(binding, id, 2, byteArrayOf(65)) }
        f.store.append(binding, id, 2, emoji.copyOfRange(2, 4))
        assertEquals(4L, f.store.seal(binding, id, 4, "a".repeat(64)).byteCount)
    }
    @Test fun discardAndExpiryRetainActiveConsumerButBlockNewConsumers() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        f.store.append(binding, id, 0, byteArrayOf(65))
        f.store.seal(binding, id, 1, "a".repeat(64))
        val consumer = f.store.acquire(binding, id)
        f.now = 101; f.store.prune()
        assertFalse(f.spools.single().erased)
        assertFailsWith<ControlProtocolException> { f.store.acquire(binding, id) }
        assertContentEquals(byteArrayOf(65), consumer.read(0, 1))
        f.store.discard(binding, id)
        consumer.close(); consumer.close()
        assertTrue(f.spools.single().erased)
        f.store.discard(binding, id)
    }
    @Test fun failedSpoolWriteInvalidatesRatherThanReusingPartiallyWrittenData() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        f.spools.single().fail = true
        assertEquals(ControlCode.PERSISTENCE_FAILED, assertFailsWith<ControlProtocolException> {
            f.store.append(binding, id, 0, byteArrayOf(65))
        }.code)
        assertTrue(f.spools.single().erased)
        assertFailsWith<ControlProtocolException> { f.store.acquire(binding, id) }
    }
    @Test fun boundedChunksHaveNoOneMiBDocumentCeiling() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        val chunk = ByteArray(ControlTransferLimits.CHUNK_BYTES) { 65 }
        repeat(17) { f.store.append(binding, id, it.toLong() * chunk.size, chunk) }
        assertEquals(17L * chunk.size, f.store.seal(binding, id, 17L * chunk.size, "a".repeat(64)).byteCount)
        assertFailsWith<ControlProtocolException> { f.store.read(binding, id, 0, chunk.size + 1) }
    }
    @Test fun capacityExpiryAndShutdownDoNotLeakOrReopenAdmission() = runTest {
        val f = Fixture()
        repeat(32) { f.store.begin(binding, "request-$it") }
        assertEquals(ControlCode.BUSY, assertFailsWith<ControlProtocolException> { f.store.begin(binding, "full") }.code)
        f.now = 101
        f.store.prune()
        assertTrue(f.spools.all { it.erased })
        assertFalse(f.store.hasRetainedTransfers())
        f.store.begin(binding, "new")
        f.store.close()
        assertTrue(f.spools.all { it.erased })
        assertFailsWith<ControlProtocolException> { f.store.begin(binding, "after-close") }
    }
    @Test fun malformedUtf8DoesNotAdvanceAdmissionOrWriteBytes() = runTest {
        val f = Fixture(); val id = f.store.begin(binding, "request").id
        for (bytes in listOf(byteArrayOf(0xc0.toByte(), 0x80.toByte()),
            byteArrayOf(0xed.toByte(), 0xa0.toByte(), 0x80.toByte()),
            byteArrayOf(0xf4.toByte(), 0x90.toByte(), 0x80.toByte(), 0x80.toByte()),
            ByteArray(ControlTransferLimits.CHUNK_BYTES + 1) { 65 })) {
            assertFailsWith<ControlProtocolException> { f.store.append(binding, id, 0, bytes) }
            assertTrue(f.spools.single().bytes.isEmpty())
        }
        f.store.append(binding, id, 0, byteArrayOf(65))
        f.store.seal(binding, id, 1, "a".repeat(64))
        val consumer = f.store.acquire(binding, id)
        f.store.discard(binding, id)
        assertTrue(f.store.hasRetainedTransfers())
        assertContentEquals(byteArrayOf(65), consumer.read(0, 1))
        consumer.close()
        assertFailsWith<ControlProtocolException> { consumer.read(0, 1) }
        assertFalse(f.store.hasRetainedTransfers())
    }
}
