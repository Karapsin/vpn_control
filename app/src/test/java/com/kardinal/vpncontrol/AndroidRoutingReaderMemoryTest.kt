package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.data.AndroidPersistedDomainSuffixes
import com.kardinal.vpncontrol.model.*
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingReaderMemoryTest {
    @Test fun routingShowStreamsFullDocumentWhileLargeGuiSnapshotsRemainReachable() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("android-routing-reader-memory-").toFile()
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:+UseSerialGC", "-Djava.library.path=${System.getProperty("java.library.path")}", "-cp", classpath,
            AndroidRoutingReaderMemoryProbe::class.java.name, directory.path)
            .redirectErrorStream(true).start()
        try {
            assertTrue("Retained GUI routing reader probe timed out", process.waitFor(60, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
            // Verify every exported domain in this independent process so the
            // receiving client's allocations do not become part of the owner budget.
            val result = ControlDocumentCodec.decodeResult(File(directory, "routing-show.json").readText())
            assertEquals(ControlCode.OK, result.code)
            assertEquals(7L, result.configurationRevision)
            val routing = result.data.getValue("routing") as ControlValue.ObjectValue
            val rules = routing.values.getValue("rules") as ControlValue.ObjectValue
            val domains = (rules.values.getValue("direct_domain_suffixes") as ControlValue.ArrayValue).values
            assertEquals(56_000, domains.size)
            domains.forEachIndexed { index, value ->
                assertEquals(AndroidRoutingReaderMemoryProbe.domain('b', index), (value as ControlValue.Text).value)
            }
        } finally {
            if (process.isAlive) process.destroyForcibly()
            directory.deleteRecursively()
        }
    }
}

/** Compacted JVM heap proxy for the native GUI-held reader failure, not an ART/Compose substitute. */
object AndroidRoutingReaderMemoryProbe {
    private const val count = 56_000
    private val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"

    @JvmStatic fun main(arguments: Array<String>) = runBlocking {
        val output = File(arguments.single(), "routing-show.json")
        readWhileGuiRetainsSnapshots(output)
        println("retained-gui-full-routing-read bytes=${output.length()} domains=$count heapLimit=${Runtime.getRuntime().maxMemory()}")
    }

    private suspend fun readWhileGuiRetainsSnapshots(output: File) {
        val old = persisted('a')
        val current = PersistedState(routingRules = RoutingRules(directDomainSuffixes = persisted('b')))
        val ui = Array(8) { ByteArray(1024 * 1024) { (it % 127).toByte() } }
        val reader = AndroidControlReader("owner", { current },
            committedSnapshot = { ControlCommitted("owner", 7L, current) }, pendingRestart = { false })
        val request = ControlRequest("gui-held-read", ControlCommand(ControlOperationId.ROUTING_SHOW), controllerId = "owner")
        val bytes = ControlDocumentCodec.encodeRequest(request).toByteArray(Charsets.UTF_8)
        println("stage=retained-gui-reader-ready heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
        val response = reader.documentResponse(bytes.inputStream(), request.requestId)
        check(response.result.code == ControlCode.OK && response.result.configurationRevision == 7L)
        output.bufferedWriter().use(response::writeTo)
        check(output.length() > 11 * 1024 * 1024)
        // These checks deliberately keep both 56,000-domain snapshots and GUI
        // allocations strongly reachable through response projection and encoding.
        check(old.size == count && old.first() == domain('a', 0) && old.last() == domain('a', count - 1))
        check(current.routingRules.directDomainSuffixes.size == count)
        check(ui.sumOf { it.size } == 8 * 1024 * 1024 && ui.all { it.last() == ((it.size - 1) % 127).toByte() })
    }

    internal fun domain(marker: Char, index: Int): String = "$marker${index.toString().padStart(5, '0')}.$suffix"

    @Suppress("DEPRECATION")
    private fun persisted(marker: Char): List<String> {
        // Fixed ASCII fixtures avoid a fixture-only UTF-16 builder peak before
        // reaching the production reader whose retained allocations are tested.
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
