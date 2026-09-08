package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.test.*

class DesktopWindowsVpnHelperPeTest {
    @Test fun emittedHeaderAndDigestAreReadInBoundedRetainedChunks() {
        val bytes = fixture()
        var biggest = 0
        val actual = DesktopWindowsVpnHelperPe.inspect(bytes.size.toLong(), 65536) { offset, count ->
            biggest = maxOf(biggest, count)
            bytes.copyOfRange(offset.toInt(), offset.toInt() + count)
        }
        assertTrue(biggest <= 8192)
        assertEquals(0x8664, actual.machine)
        assertFalse(actual.clrHeader)
        assertEquals(0x800, actual.dependentLoadFlags)
        assertEquals(MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }, actual.sha256)
        assertEquals(bytes.size.toLong(), actual.size)
    }

    @Test fun malformedDirectoriesAndSectionAliasesCannotSelectArbitraryBytes() {
        val transforms: List<(ByteBuffer) -> Unit> = listOf(
            { it.putInt(0x3c, Int.MAX_VALUE) }, { it.putShort(0x84, 0xaa64.toShort()) },
            { it.putShort(0x86, 0) }, { it.putShort(0x94, 239) },
            { it.putInt(0x98 + 108, Int.MAX_VALUE) },
            { it.putInt(0x98 + 112 + 10 * 8, 0x3000) },
            { it.putInt(0x98 + 116 + 10 * 8, Int.MAX_VALUE) },
            { it.putInt(0x300, 79) },
            { it.putShort(0x86, 2); for (index in 0 until 40) it.put(0x188 + 40 + index, it.get(0x188 + index)) },
        )
        for (change in transforms) {
            val bytes = fixture()
            change(ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN))
            assertFails { DesktopWindowsVpnHelperPe.inspect(bytes.size.toLong(), 65536) { offset, count ->
                bytes.copyOfRange(offset.toInt(), offset.toInt() + count)
            } }
        }
    }

    @Test fun shortReadsAndOversizedImagesFailWithoutLargeAllocation() {
        assertFails { DesktopWindowsVpnHelperPe.inspect(65537, 65536) { _, _ -> error("Must reject size before reading") } }
        assertFails { DesktopWindowsVpnHelperPe.inspect(4096, 65536) { _, count -> ByteArray(count - 1) } }
    }

    private fun fixture(): ByteArray = ByteArray(16384).also { bytes ->
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        buffer.put(0, 0x4d); buffer.put(1, 0x5a); buffer.putInt(0x3c, 0x80)
        buffer.putInt(0x80, 0x4550); buffer.putShort(0x84, 0x8664.toShort()); buffer.putShort(0x86, 1)
        buffer.putShort(0x94, 240); buffer.putShort(0x98, 0x20b); buffer.putInt(0x98 + 108, 16)
        buffer.putInt(0x98 + 112 + 10 * 8, 0x1100); buffer.putInt(0x98 + 116 + 10 * 8, 80)
        buffer.putInt(0x188 + 8, 0x2000); buffer.putInt(0x188 + 12, 0x1000)
        buffer.putInt(0x188 + 16, 0x2000); buffer.putInt(0x188 + 20, 0x200)
        buffer.putInt(0x300, 80); buffer.putShort(0x300 + 78, 0x800)
    }
}
