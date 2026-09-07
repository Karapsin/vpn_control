package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.control.ControlTransferSpool
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class AndroidNativeStringTest {
    @Test fun boundedAsciiReadsPreserveNulAndChunkBoundaries() {
        val expected = buildString { repeat(150_000) { append((it % 128).toChar()) } }
        val chunks = mutableListOf<ByteArray>()
        val reader = object : NativeStringTestReader {
            override fun read(offset: Long, count: Int): ByteArray {
                assertTrue(count in 1..65536)
                return ByteArray(count) { expected[offset.toInt() + it].code.toByte() }.also(chunks::add)
            }
        }
        assertEquals(expected, AndroidNativeStringTestHooks.construct(reader, expected.length, true, false))
        assertEquals(3, chunks.size)
        assertTrue(chunks.all { chunk -> chunk.all { it == 0.toByte() } })
        assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
    }

    @Test fun utf16PreservesEveryCodeUnitAndLoneSurrogates() {
        val expected = buildString { for (unit in 0..65535) append(unit.toChar()); append("\uD800x\uDC00\u0000") }
        val reader = object : NativeStringTestReader {
            override fun read(offset: Long, count: Int) = ByteArray(count) {
                val position = offset.toInt() + it
                val unit = expected[position / 2].code
                (if (position % 2 == 0) unit ushr 8 else unit).toByte()
            }
        }
        assertEquals(expected, AndroidNativeStringTestHooks.construct(reader, expected.length, false, false))
        assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
    }

    @Test fun emptyInputDoesNotAllocateOrRead() {
        val reader = object : NativeStringTestReader {
            override fun read(offset: Long, count: Int): ByteArray = error("Empty input was read")
        }
        assertEquals("", AndroidNativeStringTestHooks.construct(reader, 0, false, true))
        assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
    }

    @Test fun malformedChunkAndAsciiAreRejectedAndFreed() {
        for (chunk in listOf(byteArrayOf(), byteArrayOf(1, 2), byteArrayOf(128.toByte()))) {
            val reader = object : NativeStringTestReader {
                override fun read(offset: Long, count: Int): ByteArray = chunk.copyOf()
            }
            assertTrue(runCatching { AndroidNativeStringTestHooks.construct(reader, 1, true, false) }.exceptionOrNull() is IOException)
            assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
        }
    }

    @Test fun originalReadAndAllocationExceptionsSurviveNativeCleanup() {
        for (failure in listOf(IOException("synthetic read failure"), OutOfMemoryError("synthetic reader pressure"))) {
            var reads = 0
            val reader = object : NativeStringTestReader {
                override fun read(offset: Long, count: Int): ByteArray {
                    if (reads++ == 1) throw failure
                    return ByteArray(count)
                }
            }
            assertSame(failure, runCatching { AndroidNativeStringTestHooks.construct(reader, 70_000, true, false) }.exceptionOrNull())
            assertEquals(2, reads)
            assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
        }
        assertEquals("ok", AndroidNativeStringTestHooks.construct(object : NativeStringTestReader {
            override fun read(offset: Long, count: Int) = byteArrayOf(111, 107)
        }, 2, true, false))
    }

    @Test fun nativeAllocationFailureDoesNotReadOrLeak() {
        val reader = object : NativeStringTestReader {
            override fun read(offset: Long, count: Int): ByteArray = error("Failed native allocation read input")
        }
        assertTrue(runCatching { AndroidNativeStringTestHooks.construct(reader, 100, true, true) }.exceptionOrNull() is OutOfMemoryError)
        assertEquals(0, AndroidNativeStringTestHooks.liveAllocations())
    }

    @Test fun productionBoundaryChecksByteCountAndReadRange() {
        var reads = 0
        val spool = object : ControlTransferSpool {
            override fun append(bytes: ByteArray) = error("not appendable")
            override fun read(offset: Long, length: Int): ByteArray { reads++; return ByteArray(length) }
            override fun sha256(): String = error("not inspected")
            override fun erase() = Unit
        }
        assertTrue(runCatching { AndroidNativeString.decode(spool, 3, false, 5) }.exceptionOrNull() is IllegalArgumentException)
        assertTrue(runCatching { AndroidNativeString.decode(spool, -1, true, -1) }.exceptionOrNull() is IllegalArgumentException)
        val reader = AndroidNativeStringReader(spool, 10, 4)
        for ((offset, count) in listOf(-1L to 1, 0L to 0, 0L to 65537, 3L to 2, Long.MAX_VALUE to 1)) {
            assertTrue(runCatching { reader.read(offset, count) }.exceptionOrNull() is IOException)
        }
        assertEquals(0, reads)
    }

    @Test fun javaStringAllocationFailureFreesNativeInputAndAllowsLaterUse() {
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx32m", "-XX:+UseSerialGC", "-Djava.library.path=${System.getProperty("java.library.path")}",
            "-cp", requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath")),
            AndroidNativeStringAllocationProbe::class.java.name).redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}

interface NativeStringTestReader { fun read(offset: Long, count: Int): ByteArray }

object AndroidNativeStringTestHooks {
    init { System.loadLibrary("vpn_control_strings") }
    @JvmStatic external fun construct(reader: NativeStringTestReader, count: Int, ascii: Boolean, failAllocation: Boolean): String
    @JvmStatic external fun liveAllocations(): Int
}

object AndroidNativeStringAllocationProbe {
    @JvmStatic fun main(arguments: Array<String>) {
        check(AndroidNativeStringTestHooks.liveAllocations() == 0)
        val retained = ByteArray(8 * 1024 * 1024) { 17 }
        var read = 0L
        val reader = object : NativeStringTestReader {
            override fun read(offset: Long, count: Int) = ByteArray(count) { 65 }.also { read += count }
        }
        val error = runCatching { AndroidNativeStringTestHooks.construct(reader, 24 * 1024 * 1024, true, false) }.exceptionOrNull()
        check(error is OutOfMemoryError) { "Expected the final Java string allocation to fail" }
        check(read == 24L * 1024 * 1024) { "Allocation failed before the NewString boundary" }
        check(AndroidNativeStringTestHooks.liveAllocations() == 0)
        check(AndroidNativeStringTestHooks.construct(reader, 2, true, false) == "AA")
        check(retained.last() == 17.toByte())
        println("NewString failure freed native input; later construction succeeded")
    }
}
