package com.kardinal.vpncontrol.data

import androidx.datastore.preferences.core.mutablePreferencesOf
import androidx.datastore.preferences.core.stringPreferencesKey
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

class AndroidPreferencesSerializerMemoryTest {
    @Test fun retainedSnapshotsDoNotRequireAnotherFullSerializedDocumentAllocation() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("android-gui-serializer-memory-").toFile()
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:+UseSerialGC", "-Djava.library.path=${System.getProperty("java.library.path")}", "-cp", classpath,
            AndroidPreferencesSerializerMemoryProbe::class.java.name, directory.path)
            .redirectErrorStream(true).start()
        try {
            assertTrue("Serializer retained-snapshot probe timed out", process.waitFor(60, TimeUnit.SECONDS))
            assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally {
            if (process.isAlive) process.destroyForcibly()
            directory.deleteRecursively()
        }
    }
}

/** Component heap proxy for the native 48 MiB GUI add failure, not an ART/Compose substitute. */
object AndroidPreferencesSerializerMemoryProbe {
    @JvmStatic fun main(arguments: Array<String>) = runBlocking {
        val directory = File(arguments.single())
        val key = stringPreferencesKey("direct_domain_suffixes")
        // The observed failure retained old/new large preferences and a live GUI
        // draft while protobuf allocated one more 11.7 MB serialized byte array.
        val old = mutablePreferencesOf(key to ascii('a')).toPreferences()
        val current = mutablePreferencesOf(key to ascii('b')).toPreferences()
        val ui = Array(8) { ByteArray(1024 * 1024) { (it % 127).toByte() } }
        val serializer = AndroidPreferencesSerializer(directory.toPath())
        val file = File(directory, "preferences.pb")
        println("stage=retained-snapshots-ready heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
        file.outputStream().use { serializer.writeTo(current, it) }
        check(file.length() > 11_716_000)
        // Cache reuse must still consume and verify every byte; both snapshots and
        // the simulated GUI allocations remain strongly reachable during the read.
        check(file.inputStream().use { serializer.readFrom(it) } === current)
        check(old[key]!!.length == 11_716_000 && old[key]!!.first() == 'a')
        check(current[key]!!.length == 11_716_000 && current[key]!!.first() == 'b')
        check(ui.sumOf { it.size } == 8 * 1024 * 1024 && ui.all { it.last() == ((it.size - 1) % 127).toByte() })
        println("retained-snapshot-write-and-verified-cache bytes=${file.length()} heapLimit=${Runtime.getRuntime().maxMemory()}")
    }

    @Suppress("DEPRECATION")
    private fun ascii(value: Char): String = java.lang.String(ByteArray(11_716_000) { value.code.toByte() }, 0).toString()
}
