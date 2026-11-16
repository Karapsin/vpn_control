package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.CandidateCountryResolver
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.UserCountryResolver
import com.kardinal.vpncontrol.model.DnsSettings
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue

/**
 * Review of 1fe2ddab: the Find Best candidate runtime (`DesktopProxyValidationRuntime.benchmarkCandidate`) created
 * `validate-<remarks>-<n>.json`, which holds the candidate's credentials, and its `.log` before it resolved sing-box and
 * prepared the probe copy, outside its `try`, so a missing sing-box or a failed probe copy returned with both left in
 * the validation folder. Inside the `try` it kept the mechanism behind native run 584d9f4c: sing-box's output went to
 * the log through a redirect the child inherited, and each file got one deletion with a refusal swallowed. The direct
 * probe (`DesktopDirectProbeProxy`) had the same shape. These tests drive the public validation runtime and the direct
 * probe; a POSIX read-only folder stands in for Windows' refusal, as in [DesktopHomeSshBootstrapCleanupTest].
 */
class DesktopValidationRuntimeCleanupTest {
    @Test fun aFindBestCandidateWithoutSingBoxLeavesNoCredentialFile() = fixture { root ->
        val validation = root.resolve("validation")
        val resolver = DesktopSingBoxResolver(validation.resolve("tools"), classLoader = StandIn(null), osNameOverride = "none")
        assumeTrue("a sing-box resolved from the environment or PATH", resolver.resolve() == null)
        val result = benchmark(validation, resolver)
        assertTrue("sing_box_missing" in result, result)
        assertEquals(emptyList(), shortLivedFiles(validation), "files left by a candidate without sing-box")
    }

    @Test fun aFindBestCandidateWhoseProbeCopyFailsLeavesNoCredentialFile() = fixture { root ->
        assumeTrue("VPN_CONTROL_SING_BOX overrides the stand-in", System.getenv("VPN_CONTROL_SING_BOX").isNullOrBlank())
        val validation = Files.createDirectories(root.resolve("validation"))
        val resolver = DesktopSingBoxResolver(validation.resolve("tools"), classLoader = StandIn(byteArrayOf(1)))
        assumeTrue("the stand-in did not resolve", resolver.resolve()?.path?.startsWith(validation.resolve("tools")) == true)
        // A folder where the probe copy belongs makes the copy fail.
        val probe = Files.createDirectories(DesktopDirectProbeRouting.probeSingBoxExecutable(validation))
        Files.writeString(probe.resolve("occupied"), "")
        val result = benchmark(validation, resolver)
        assertTrue("probe_binary_failed" in result, result)
        assertEquals(emptyList(), shortLivedFiles(validation), "files left by a candidate whose probe copy failed")
    }

    @Test fun theDirectProbeWithoutSingBoxLeavesNoFile() = fixture { root ->
        val validation = root.resolve("validation")
        val resolver = DesktopSingBoxResolver(validation.resolve("tools"), classLoader = StandIn(null), osNameOverride = "none")
        assumeTrue("a sing-box resolved from the environment or PATH", resolver.resolve() == null)
        val failure = runCatching { runBlocking { DesktopDirectProbeProxy(validation, resolver).useProxy { "unreachable" } } }
        assertEquals(resolver.missingMessage(), failure.exceptionOrNull()?.message)
        assertEquals(emptyList(), shortLivedFiles(validation), "files left by a direct probe without sing-box")
    }

    @Test fun aFindBestCandidateKeepsNoLogAndRemovesItsFilesOnceRefusalsEnd() = fixture { root ->
        assumeFalse("POSIX permissions stand in for Windows' refusals", isWindows())
        assumeTrue("VPN_CONTROL_SING_BOX overrides the stand-in", System.getenv("VPN_CONTROL_SING_BOX").isNullOrBlank())
        assumeFalse("this account deletes in a read-only folder", deletesInReadOnlyFolder(root))
        val validation = Files.createDirectories(root.resolve("validation"))
        val signal = Files.createDirectory(root.resolve("signal"))
        val resolver = DesktopSingBoxResolver(validation.resolve("tools"), classLoader = StandIn(standIn(signal)))
        assumeTrue("the stand-in did not resolve", resolver.resolve()?.path?.startsWith(validation.resolve("tools")) == true)
        var pid: Long? = null
        try {
            // Nothing listens on the candidate's port, so the candidate ends proxy_not_ready after its startup bound.
            val result = benchmark(validation, resolver)
            pid = Files.readString(signal.resolve("started")).trim().split(' ').first().toLong()
            assertTrue("proxy_not_ready" in result, result)
            val atStart = Files.readAllLines(signal.resolve("files")).filter(String::isNotBlank)
            assertEquals(1, atStart.size, "the stand-in saw $atStart")
            assertTrue(atStart.single().startsWith("validate-fixture-") && atStart.single().endsWith(".json"), "$atStart")
            assertEquals(emptyList(), shortLivedFiles(validation), "files left once the candidate was judged")
            assertFalse(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false), "the stand-in still ran")
        } finally {
            (pid ?: runCatching { Files.readString(signal.resolve("started")).trim().split(' ').first().toLong() }.getOrNull())
                ?.let { ProcessHandle.of(it).ifPresent(ProcessHandle::destroyForcibly) }
            Files.setPosixFilePermissions(validation, PosixFilePermissions.fromString("rwx------"))
        }
    }

    private fun benchmark(validation: Path, resolver: DesktopSingBoxResolver): String {
        val runtime = DesktopProxyValidationRuntime(validation, resolver, UserCountryResolver { null }, CandidateCountryResolver { null })
        val candidate = PreflightResult(LocationConfigs.decodeStoredLocation(LINK), 1.0, "fixture")
        val settings = DesktopValidationSettings(startupTimeoutMillis = 1_500L, profileTimeoutMillis = 15_000L)
        val result = runBlocking { runtime.benchmarkPreflightCandidate(candidate, DnsSettings(), BenchmarkUrls(), settings) }
        return result.fold({ it.detail }, { "failed: $it" })
    }

    /**
     * Stand-in for sing-box (`run -c <config>`): it notes the validation files present when it starts, makes the folder
     * read-only until 0.4 s after it is gone, reports its pid and port, and never listens.
     */
    private fun standIn(signal: Path): ByteArray = """
        |#!/bin/sh
        |config="${'$'}3"
        |port=${'$'}(sed -n 's/.*"listen_port": *\([0-9][0-9]*\).*/\1/p' "${'$'}config" | head -n 1)
        |dir=${'$'}(pwd)
        |ls "${'$'}dir" | grep -e '^validate-' -e '^direct-probe-' > "$signal/files"
        |chmod u-w "${'$'}dir"
        |( while kill -0 ${'$'}${'$'} 2>/dev/null; do sleep 0.05; done; sleep 0.4; chmod u+w "${'$'}dir" ) </dev/null >/dev/null 2>&1 &
        |printf '%s %s\n' "${'$'}${'$'}" "${'$'}port" > "$signal/started.tmp" && mv "$signal/started.tmp" "$signal/started"
        |while :; do sleep 0.1; done
        |""".trimMargin().toByteArray(StandardCharsets.US_ASCII)

    /** Serves the stand-in as the bundled sing-box of every platform, or nothing. */
    private class StandIn(private val bytes: ByteArray?) : ClassLoader(null) {
        override fun getResourceAsStream(name: String): InputStream? =
            bytes?.takeIf { name.startsWith("bin/") }?.let(::ByteArrayInputStream)
    }

    private fun deletesInReadOnlyFolder(root: Path): Boolean {
        val folder = Files.createDirectory(root.resolve("privilege-probe"))
        val file = Files.createFile(folder.resolve("probe"))
        Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("r-x------"))
        return try { Files.deleteIfExists(file) } catch (_: java.io.IOException) { false }
            finally { Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwx------")) }
    }

    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("vpn-control-validation-cleanup")
        try {
            block(root)
        } finally {
            if (!isWindows()) {
                Files.walk(root).use { paths ->
                    paths.filter(Files::isDirectory).forEach { folder ->
                        runCatching { Files.setPosixFilePermissions(folder, PosixFilePermission.values().toSet()) }
                    }
                }
            }
            root.toFile().deleteRecursively()
        }
    }

    private companion object {
        const val LINK = "trojan://fixture-secret-password@127.0.0.1:443?security=tls&sni=example.test#Fixture"

        fun isWindows() = System.getProperty("os.name").startsWith("Windows")

        fun shortLivedFiles(folder: Path): List<String> = if (!Files.isDirectory(folder)) emptyList() else
            Files.list(folder).use { paths ->
                paths.map { it.fileName.toString() }.filter { it.startsWith("validate-") || it.startsWith("direct-probe-") }
                    .sorted().toList()
            }
    }
}
