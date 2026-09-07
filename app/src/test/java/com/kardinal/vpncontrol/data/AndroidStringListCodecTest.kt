package com.kardinal.vpncontrol.data

import java.io.File
import java.util.concurrent.TimeUnit
import com.kardinal.vpncontrol.AndroidControlTransferSpool
import com.kardinal.vpncontrol.control.ControlTransferSpool
import org.junit.Assert.*
import org.junit.Test

class AndroidStringListCodecTest {
    @Test fun ownedPersistedListFitsAlongsideRetainedState() {
        val classpath = listOf(AndroidStringListMemoryProbe::class.java, AndroidStringListCodec::class.java, kotlin.Unit::class.java)
            .map { File(it.protectionDomain.codeSource.location.toURI()).path }.distinct().joinToString(File.pathSeparator)
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path, "-Xmx48m", "-cp", classpath,
            AndroidStringListMemoryProbe::class.java.name).redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
    @Test fun encodingPreservesLegacySeparatorsAndEveryUtf16Unit() {
        val units = buildString { for (code in 0..65535) append(code.toChar()) }
        val ascii = buildString { for (code in 0..127) append(code.toChar()) }
        for (values in listOf(emptyList(), listOf(""), listOf("", "", ""), listOf("one", "two"),
            listOf(ascii, ascii.reversed()), listOf(units, "\uD800", "line\nbreak", "\uDC00"))) {
            assertEquals(values.joinToString("\n"), AndroidStringListCodec.encode(values))
            val owned = values.toTypedArray<String?>()
            assertEquals(values.joinToString("\n"), AndroidStringListCodec.encodeOwned(owned))
            assertTrue(owned.all { it == null })
        }
    }

    @Test fun privateSpoolPreservesUnitsAndCleansUpAfterSuccessAndFailure() {
        val directory = java.nio.file.Files.createTempDirectory("routing-encoding-")
        try {
            val units = buildString { for (code in 0..65535) append(code.toChar()) }
            for (values in listOf(listOf("a".repeat(70000), "b"), listOf(units, "\uD800", "\uDC00"))) {
                val owned = values.toTypedArray<String?>()
                assertEquals(values.joinToString("\n"), AndroidStringListCodec.encodeOwned(owned) {
                    AndroidControlTransferSpool.create(directory)
                })
                assertTrue(owned.all { it == null })
                assertEquals(0L, java.nio.file.Files.list(directory).use { it.count() })
            }
            var erased = false
            val rules = AndroidPreparedRouting(com.kardinal.vpncontrol.model.RoutingRules(directDomainSuffixes = listOf("old.test", "new.test")))
            assertTrue(runCatching { rules.consume {
                object : ControlTransferSpool {
                    override fun append(bytes: ByteArray) { throw java.io.IOException("synthetic storage failure") }
                    override fun read(offset: Long, length: Int): ByteArray = error("not reached")
                    override fun sha256(): String = error("not reached")
                    override fun erase() { erased = true }
                }
            } }.exceptionOrNull() is java.io.IOException)
            assertTrue(erased)
            assertTrue(runCatching { rules.consume() }.exceptionOrNull() is IllegalStateException)
        } finally { java.nio.file.Files.delete(directory) }
    }
}

object AndroidStringListMemoryProbe {
    @JvmStatic fun main(args: Array<String>) {
        val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
        // The production import owns these slots and releases them while encoding.
        // The earlier non-consuming List probe reproduced the old retention peak;
        // keep the same input, heap and extra 7MiB pressure for this lifecycle fix.
        val values = Array<String?>(56_000) { "d$it.$suffix" }
        val first = requireNotNull(values.first())
        val last = requireNotNull(values.last())
        val retainedRequest = "x".repeat(7 * 1024 * 1024)
        val encoded = AndroidStringListCodec.encodeOwned(values)
        check(encoded.startsWith(first) && encoded.endsWith(last))
        check(encoded.count { it == '\n' } == values.size - 1)
        check(values.all { it == null })
        check(retainedRequest.hashCode() != 0)
    }
}
