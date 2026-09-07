package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import kotlin.test.*

class DesktopExportUtf8Test {
    @Test fun unicodeBoundariesAndMalformedSurrogatesMatchExistingExports() {
        for (text in listOf("", "a".repeat(8191) + "😀東京", "\uD800x\uDC00", "😀東京".repeat(10000))) {
            val output = ByteArrayOutputStream()
            DesktopExportUtf8.encode(text) { bytes, count ->
                assertTrue(count in 1..8192)
                output.write(bytes, 0, count)
            }
            assertContentEquals(text.toByteArray(Charsets.UTF_8), output.toByteArray())
            assertEquals(output.size().toLong(), DesktopExportUtf8.byteCount(text))
        }
    }

    @Test fun largeInputIsNotConvertedToAnIntermediateStringOrWholeByteArray() {
        val pattern = "東京😀\n"
        val repetitions = 1_000_000
        val text = object : CharSequence {
            override val length = pattern.length * repetitions
            override fun get(index: Int): Char = pattern[index % pattern.length]
            override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = error("Unexpected copy")
            override fun toString(): String = error("Unexpected whole-document copy")
        }
        val expected = MessageDigest.getInstance("SHA-256")
        val patternBytes = pattern.toByteArray(Charsets.UTF_8)
        repeat(repetitions) { expected.update(patternBytes) }
        val actual = MessageDigest.getInstance("SHA-256")
        var count = 0L
        DesktopExportUtf8.encode(text) { bytes, size ->
            assertTrue(size in 1..8192)
            actual.update(bytes, 0, size)
            count += size
        }
        assertEquals(patternBytes.size.toLong() * repetitions, count)
        assertContentEquals(expected.digest(), actual.digest())
    }

    @Test fun sinkFailureStopsEncodingImmediately() {
        var calls = 0
        assertFailsWith<java.io.IOException> {
            DesktopExportUtf8.encode("x".repeat(100_000)) { _, _ ->
                calls++
                throw java.io.IOException("test")
            }
        }
        assertEquals(1, calls)
    }
}
