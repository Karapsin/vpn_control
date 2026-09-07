package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.AndroidControlInputSpool
import com.kardinal.vpncontrol.AndroidControlTransferSpool
import com.kardinal.vpncontrol.model.RoutingRules
import java.io.File
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingPreparedInputMemoryTest {
    @Test fun replacingRulesDoesNotMaterializeAnUnusedOldDomainPoolWithRetainedSnapshots() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("android-routing-preparation-memory-").toFile()
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:+UseSerialGC", "-Djava.library.path=${System.getProperty("java.library.path")}", "-cp", classpath,
            AndroidRoutingPreparedInputMemoryProbe::class.java.name, directory.path)
            .redirectErrorStream(true).start()
        try {
            assertTrue("Routing preparation retained-snapshot probe timed out", process.waitFor(60, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally {
            if (process.isAlive) process.destroyForcibly()
            directory.deleteRecursively()
        }
    }
}

/** Compacting JVM allocation-boundary proxy; full edits still require native ART evidence. */
object AndroidRoutingPreparedInputMemoryProbe {
    private const val count = 56_000
    private val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"

    @JvmStatic fun main(arguments: Array<String>) {
        val directory = File(arguments.single()).toPath()
        val prior = persisted('a')
        val current = RoutingRules(directDomainSuffixes = persisted('b'))
        val ui = Array(8) { ByteArray(1024 * 1024) { (it % 127).toByte() } }
        val input = AndroidControlInputSpool(AndroidControlTransferSpool.create(directory))
        val document = """{"direct_domain_suffixes":["replacement.example"],"proxy_packages":[]}"""
        input.append(document)
        input.seal()
        println("stage=retained-preparation-ready heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
        val prepared = AndroidRoutingPreparedInput(input).apply { reuseMatchingTokens(current) }.prepareForStorage()
        check(prepared.matches(RoutingRules(directDomainSuffixes = listOf("replacement.example"))))
        val encoded = prepared.consume { AndroidControlTransferSpool.create(directory) }
        check(encoded.directDomainSuffixes == "replacement.example")
        // Keep every old domain and the GUI allocations strongly reachable until
        // preparation completes. A small replacement isolates the unnecessary
        // old-pool allocation from the separate full-import peak.
        check(prior.size == count && prior.first() == domain('a', 0) && prior.last() == domain('a', count - 1))
        check(current.directDomainSuffixes.size == count && current.directDomainSuffixes.first() == domain('b', 0))
        check(ui.sumOf { it.size } == 8 * 1024 * 1024 && ui.all { it.last() == ((it.size - 1) % 127).toByte() })
        println("retained-gui-preparation domains=$count heapLimit=${Runtime.getRuntime().maxMemory()}")
    }

    private fun domain(marker: Char, index: Int): String = "$marker${index.toString().padStart(5, '0')}.$suffix"

    @Suppress("DEPRECATION")
    private fun persisted(marker: Char): List<String> {
        val bytes = ByteArray(count * (domain(marker, 0).length + 1))
        var offset = 0
        repeat(count) { index ->
            val entry = (domain(marker, index) + "\n").toByteArray(Charsets.US_ASCII)
            entry.copyInto(bytes, offset)
            offset += entry.size
        }
        return AndroidPersistedDomainSuffixes.decode(java.lang.String(bytes, 0).toString())
    }
}
