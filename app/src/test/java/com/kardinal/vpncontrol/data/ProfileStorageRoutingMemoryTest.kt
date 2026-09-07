package com.kardinal.vpncontrol.data

import android.content.Context
import android.content.ContextWrapper
import com.kardinal.vpncontrol.model.RoutingRules
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProfileStorageRoutingMemoryTest {
    @Test fun guiRoutingSaveKeepsLargePersistedListWithin48MiB() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("profile-routing-memory-").toFile()
        try {
            // SerialGC keeps the 48MiB child reproducible; default G1 can exhaust the
            // full Android unit-test runtime before it reaches the persistence path.
            val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
                "-Xmx48m", "-XX:+UseSerialGC", "-Djava.library.path=${System.getProperty("java.library.path")}", "-cp", classpath,
                ProfileStorageRoutingMemoryProbe::class.java.name, directory.path).redirectErrorStream(true).start()
            try {
                assertTrue(process.waitFor(90, TimeUnit.SECONDS))
                assertEquals(process.inputStream.bufferedReader().readText(), 0, process.exitValue())
            } finally { if (process.isAlive) process.destroyForcibly() }
        } finally { directory.deleteRecursively() }
    }
}

object ProfileStorageRoutingMemoryProbe {
    @JvmStatic fun main(args: Array<String>) = runBlocking {
        val root = File(requireNotNull(args.firstOrNull())).also { check(it.mkdirs() || it.isDirectory) }
        val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
        val domains = List(56_000) { "d$it.$suffix" }
        val first = domains.first()
        val last = domains.last()
        // The rendered Rules editor keeps its source list and other UI state live while saving.
        val retainedUi = "x".repeat(7 * 1024 * 1024)
        val storage = ProfileStorage(ProfileStorageMemoryContext(root))
        storage.updateRoutingRules(RoutingRules(directDomainSuffixes = domains))
        val stored = storage.configurationSnapshot().value.routingRules.directDomainSuffixes
        check(stored.size == domains.size && stored.first() == first && stored.last() == last)
        check(domains.first() == first && domains.last() == last)
        check(retainedUi.hashCode() != 0)
    }
}

private class ProfileStorageMemoryContext(private val root: File) : ContextWrapper(null) {
    private val files = File(root, "files").also { check(it.mkdirs() || it.isDirectory) }
    private val cache = File(root, "cache").also { check(it.mkdirs() || it.isDirectory) }
    override fun getApplicationContext(): Context = this
    override fun getFilesDir(): File = files
    override fun getCacheDir(): File = cache
    override fun getPackageName(): String = "com.kardinal.vpncontrol.memory"
}
