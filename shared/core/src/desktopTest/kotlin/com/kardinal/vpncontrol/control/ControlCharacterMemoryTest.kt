package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlValue
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ControlCharacterMemoryTest {
    @Test fun elevenMiBAsciiDoesNotRequireAnExponentialUtf16Accumulator() {
        runProbe("decode")
    }
    @Test fun fingerprintDoesNotMaterializeAnotherLargeJsonString() {
        runProbe("fingerprint")
    }
    @Test fun routingNormalizationDoesNotJoinAndResplitAllDomains() {
        runProbe("routing")
    }
    private fun runProbe(mode: String) {
        val classes = listOf(ControlCharacterMemoryProbe::class.java, ControlDocumentCodec::class.java,
            ControlValue::class.java, kotlin.Unit::class.java, kotlinx.serialization.json.Json::class.java,
            kotlinx.serialization.KSerializer::class.java)
        val classpath = classes.map { File(it.protectionDomain.codeSource.location.toURI()).path }
            .distinct().joinToString(File.pathSeparator)
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:-CompactStrings", "-cp", classpath, ControlCharacterMemoryProbe::class.java.name, mode)
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "bounded parser subprocess")
            assertEquals(0, process.exitValue(), process.inputStream.bufferedReader().readText())
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}

object ControlCharacterMemoryProbe {
    @JvmStatic fun main(args: Array<String>) {
        if (args.single() == "routing") {
            val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
            val values = List(56_000) { "d$it.$suffix" }
            val normalized = com.kardinal.vpncontrol.model.RoutingRules.parseDirectDomainSuffixes(values)
            check(normalized == values)
            return
        }
        val prefix = """{"schemaVersion":1,"requestId":"r","interactive":false,"asynchronous":false,"command":{"operation":"locations.import","arguments":{"input":""""
        val suffix = "\"}}}"
        val size = 11 * 1024 * 1024 + 17
        var position = 0
        val result = ControlDocumentCodec.decodeRequest(ControlCharacterSource {
            val index = position++
            when {
                index < prefix.length -> prefix[index].code
                index < prefix.length + size -> 'x'.code
                index < prefix.length + size + suffix.length -> suffix[index - prefix.length - size].code
                else -> -1
            }
        })
        val value = (result.command.arguments.getValue("input") as ControlValue.Text).value
        check(value.length == size && value.all { it == 'x' })
        if (args.single() == "fingerprint") {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
            val sink = object : java.io.OutputStream() {
                override fun write(value: Int) = digest.update(value.toByte())
                override fun write(bytes: ByteArray, offset: Int, count: Int) = digest.update(bytes, offset, count)
            }
            java.io.OutputStreamWriter(sink, Charsets.UTF_8).buffered(8192).use {
                ControlDocumentCodec.writeValues(result.command.arguments, it)
                it.append("\u0000null\u0000false\u0000scheduled=false")
            }
            check(digest.digest().size == 32)
        }
    }
}
