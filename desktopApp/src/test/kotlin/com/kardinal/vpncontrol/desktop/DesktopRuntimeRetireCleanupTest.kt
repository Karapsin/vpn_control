package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.RoutingRules
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.PrintStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue

/**
 * Native run d71253c2-2588-4735-8222-6d1dd0dd2e27 (Windows, package 2.2.18): a proxy-only runtime with SSH Routing,
 * turned on, used for a refresh and turned `off`, answered OK and stopped, and its `candidate-*` folder stayed in the
 * workspace's runtime folder ("runtime-candidates-left"). That folder holds the runtime's captured SSH key copy, its
 * configuration (the location's credentials) and its log until the runtime is retired. The manager retired it once
 * right after a timed wait for the child, retried once at once, and swallowed the refusal, while Windows refuses a
 * deletion for a while after a child was told to end: the child's handles (the log redirect, which the JVM opens
 * without delete sharing, among them) close only as its process object ends, and a scanner may hold a fresh file.
 *
 * The first test drives the public manager with a stand-in for sing-box (the production preflight, launch, log redirect,
 * stop and retirement) and refuses deletions the POSIX way: the stand-in makes its candidate folder read-only and a
 * watcher makes it writable again 0.4 s after the stand-in is gone. The test listens on the ports the configuration
 * names, as sing-box would.
 */
class DesktopRuntimeRetireCleanupTest {
    @Test fun deletionsRefusedUntilShortlyAfterTheRuntimeEndedLeaveNoCandidateFolder() {
        val outcome = connectAndStop(restoreAfterExit = true)
        assertTrue(outcome.keyCopiedAtStart, "the candidate held no captured key copy while it ran")
        assertEquals(emptyList(), outcome.leftAfterStop, "runtime candidate folders left once off returned")
        assertFalse(outcome.standInAliveAfterStop, "the stand-in still ran once off returned")
    }

    @Test fun aRefusalThatOutlastsTheRetriesIsReportedByLeafAndRetiredAtTheNextStop() {
        val outcome = connectAndStop(restoreAfterExit = false)
        assertEquals(1, outcome.leftAfterStop.size, "the refused candidate folder stays until a later retirement")
        assertTrue(outcome.reportAfterStop.lines().any { line ->
            line.startsWith("$CONNECTION_RUNTIME_REPORT_LABEL: ") && "was not removed after" in line
        }, "nothing on stderr named the refused retirement: ${outcome.reportAfterStop}")
        assertFalse(outcome.reportAfterStop.contains(outcome.root.toString()), "the report names a folder")
        assertFalse(outcome.reportAfterStop.contains(KEY_BODY), "the report holds key material")
        assertEquals(emptyList(), outcome.leftAfterNextStop, "the next stop did not retire the refused candidate")
    }

    @Test fun theRuntimesProcessObjectIsAwaitedOnceItsExitCodeIsSet() {
        // Windows: a timed waitFor and isAlive answer from the exit code, set before the child's handles are closed;
        // only the untimed waitFor waits on the process object, signalled after them.
        val released = CountDownLatch(1)
        val process = ExitCodeFirstProcess(released)
        val closed = CountDownLatch(1)
        thread(name = "runtime-close", isDaemon = true) {
            DesktopLocalRuntimeProcess(process).close()
            closed.countDown()
        }
        assertTrue(process.untimedWait.await(5, TimeUnit.SECONDS), "close never waited on the process object")
        assertFalse(closed.await(300, TimeUnit.MILLISECONDS), "close returned before the process object ended")
        released.countDown()
        assertTrue(closed.await(5, TimeUnit.SECONDS), "close did not return once the process object ended")
    }

    @Test fun aCandidateTheOsKeepsRefusingTakesOneRetryBoundAndIsReportedPerLeaf() {
        // A runtime's retirement removes four paths; refused together they wait one bound, not one per path.
        val slept = mutableListOf<Long>()
        val reports = mutableListOf<String>()
        val tries = mutableMapOf<String, Int>()
        val cleanup = DesktopBootstrapCleanup(
            delete = { path -> tries[path.fileName.toString()] = (tries[path.fileName.toString()] ?: 0) + 1; throw java.nio.file.AccessDeniedException(path.toString()) },
            gone = { false }, sleep = { slept += it }, report = { reports += it }, label = "Connection runtime")
        val folder = Path.of("runtime", "candidate-1")
        val paths = listOf(folder.resolve("home-ssh-private-key"), folder.resolve("config.json"), folder.resolve("runtime.log"), folder)
        assertEquals(paths, cleanup.removeAll(paths))
        assertEquals(DesktopBootstrapCleanup.RETRY_DELAYS_MILLIS, slept, "one backoff for the whole set")
        assertEquals(mapOf("home-ssh-private-key" to 8, "config.json" to 8, "runtime.log" to 8, "candidate-1" to 8), tries)
        assertEquals(listOf("home-ssh-private-key", "config.json", "runtime.log", "candidate-1").map { leaf ->
            "Connection runtime: $leaf was not removed after 8 attempts (AccessDeniedException)"
        }, reports)
    }

    @Test fun aFolderRefusedOnlyUntilItsFilesAreGoneIsRemovedInTheSamePass() {
        val present = mutableSetOf("home-ssh-private-key", "config.json", "runtime.log", "candidate-2")
        val slept = mutableListOf<Long>()
        val cleanup = DesktopBootstrapCleanup(
            delete = { path ->
                val leaf = path.fileName.toString()
                if (leaf == "candidate-2" && present.size > 1) throw java.nio.file.DirectoryNotEmptyException(path.toString())
                present -= leaf
            },
            gone = { path -> path.fileName.toString() !in present }, sleep = { slept += it }, report = { fail("reported $it") })
        val folder = Path.of("runtime", "candidate-2")
        assertEquals(emptyList(), cleanup.removeAll(listOf(folder.resolve("home-ssh-private-key"), folder.resolve("config.json"),
            folder.resolve("runtime.log"), folder)))
        assertEquals(emptyList(), slept, "nothing was refused, so nothing waited")
    }

    private class Outcome(
        val root: Path,
        val keyCopiedAtStart: Boolean,
        val leftAfterStop: List<String>,
        val standInAliveAfterStop: Boolean,
        val reportAfterStop: String,
        val leftAfterNextStop: List<String>,
    )

    private fun connectAndStop(restoreAfterExit: Boolean): Outcome {
        assumeFalse("POSIX permissions stand in for Windows' refusals", isWindows())
        assumeTrue("VPN_CONTROL_SING_BOX overrides the stand-in", System.getenv("VPN_CONTROL_SING_BOX").isNullOrBlank())
        var outcome: Outcome? = null
        fixture { root ->
            assumeFalse("this account deletes in a read-only folder", deletesInReadOnlyFolder(root))
            val workspace = root.resolve("workspace")
            val runtime = Files.createDirectories(workspace.resolve("runtime"))
            val signal = Files.createDirectory(root.resolve("signal"))
            DesktopHomeSshCredentialStore(workspace).importPrivateKey(KEY)
            val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = StandIn(standIn(signal, restoreAfterExit)))
            assumeTrue("the stand-in did not resolve", resolver.resolve()?.path?.startsWith(runtime.resolve("tools")) == true)
            val manager = DesktopProxyRuntimeManager(MemoryRuntimeConfigStore(), runtime, singBoxResolver = resolver)
            val listener = StandInListener(signal)
            val report = ByteArrayOutputStream()
            val stderr = System.err
            var pid: Long? = null
            try {
                runBlocking {
                    manager.start(LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#Fixture"), RoutingRules(),
                        DnsSettings(), AppMode.PROXY_ONLY, null, SETTINGS).getOrThrow()
                }
                pid = listener.pid
                System.setErr(PrintStream(TeeStream(stderr, report), true, StandardCharsets.UTF_8))
                try {
                    runBlocking { manager.stop().getOrThrow() }
                } finally {
                    System.setErr(stderr)
                }
                val left = candidates(runtime)
                val alive = pid?.let { ProcessHandle.of(it).map(ProcessHandle::isAlive).orElse(false) } ?: false
                restoreWritable(root)
                runBlocking { manager.stop().getOrThrow() }
                outcome = Outcome(root, listener.keyCopied, left, alive, report.toString(StandardCharsets.UTF_8), candidates(runtime))
            } finally {
                System.setErr(stderr)
                listener.close()
                (pid ?: listener.pid)?.let { ProcessHandle.of(it).ifPresent(ProcessHandle::destroyForcibly) }
                restoreWritable(root)
                runCatching { runBlocking { manager.stop() } }
            }
        }
        return checkNotNull(outcome)
    }

    /** Listens on every inbound port of the configuration the stand-in was started with, as sing-box would. */
    private class StandInListener(private val signal: Path) : AutoCloseable {
        @Volatile var pid: Long? = null
        @Volatile var keyCopied = false
        private val servers = java.util.concurrent.CopyOnWriteArrayList<ServerSocket>()
        @Volatile private var closed = false
        private val worker = thread(name = "runtime-stand-in-listener", isDaemon = true) { serve() }

        private fun serve() {
            val started = signal.resolve("started")
            val deadline = System.nanoTime() + 30_000_000_000L
            while (!Files.exists(started)) {
                if (closed || System.nanoTime() > deadline) return
                Thread.sleep(20)
            }
            val config = Path.of(Files.readString(started).trim().substringAfter(' '))
            pid = Files.readString(started).trim().substringBefore(' ').toLong()
            keyCopied = Files.isRegularFile(config.resolveSibling("home-ssh-private-key"))
            val ports = Json.parseToJsonElement(Files.readString(config)).jsonObject.getValue("inbounds").jsonArray
                .mapNotNull { it.jsonObject["listen_port"]?.jsonPrimitive?.int }.distinct()
            for (port in ports) {
                val server = ServerSocket(port, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                servers += server
                thread(name = "runtime-stand-in-port-$port", isDaemon = true) {
                    while (!closed) {
                        try { server.accept().close() } catch (_: SocketException) { return@thread }
                    }
                }
            }
        }

        override fun close() {
            closed = true
            servers.forEach { runCatching { it.close() } }
            worker.join(5_000)
        }
    }

    /** Serves the stand-in as the bundled sing-box of every platform. */
    private class StandIn(private val bytes: ByteArray) : ClassLoader(null) {
        override fun getResourceAsStream(name: String): InputStream? =
            bytes.takeIf { name.startsWith("bin/") }?.let(::ByteArrayInputStream)
    }

    private class TeeStream(private val first: OutputStream, private val second: OutputStream) : OutputStream() {
        override fun write(b: Int) { first.write(b); second.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) { first.write(b, off, len); second.write(b, off, len) }
        override fun flush() { first.flush(); second.flush() }
    }

    /** A child whose exit code is set (timed waitFor, isAlive) while its process object has not ended yet. */
    private class ExitCodeFirstProcess(private val released: CountDownLatch) : Process() {
        val untimedWait = CountDownLatch(1)
        override fun getOutputStream(): OutputStream = OutputStream.nullOutputStream()
        override fun getInputStream(): InputStream = InputStream.nullInputStream()
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun waitFor(): Int {
            untimedWait.countDown()
            released.await()
            return 0
        }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true
        override fun exitValue(): Int = 0
        override fun isAlive(): Boolean = false
        override fun destroy() = Unit
        override fun pid(): Long = 4242
    }

    private class MemoryRuntimeConfigStore : com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore {
        @Volatile private var config: String? = null
        override suspend fun readRuntimeConfig(): String? = config
        override suspend fun writeRuntimeConfig(configJson: String) { config = configJson }
        override suspend fun clearRuntimeConfig() { config = null }
    }

    private fun standIn(signal: Path, restoreAfterExit: Boolean): ByteArray {
        val restore = if (restoreAfterExit) {
            "( while kill -0 \$\$ 2>/dev/null; do sleep 0.05; done; sleep 0.4; chmod u+w \"\$dir\" ) </dev/null >/dev/null 2>&1 &\n"
        } else ""
        val script = """
            |#!/bin/sh
            |# Stand-in for sing-box: version, check -c <config> and run -c <config>.
            |case "${'$'}1" in
            |  version) echo "sing-box version stand-in"; exit 0 ;;
            |  check) exit 0 ;;
            |esac
            |config="${'$'}3"
            |dir=${'$'}(dirname "${'$'}config")
            |chmod u-w "${'$'}dir"
            |""".trimMargin() + "\n" + restore + """
            |printf '%s %s\n' "${'$'}${'$'}" "${'$'}config" > "$signal/started.tmp" && mv "$signal/started.tmp" "$signal/started"
            |while :; do sleep 0.1; done
            |""".trimMargin() + "\n"
        return script.toByteArray(StandardCharsets.US_ASCII)
    }

    private fun deletesInReadOnlyFolder(root: Path): Boolean {
        val folder = Files.createDirectory(root.resolve("privilege-probe"))
        val file = Files.createFile(folder.resolve("probe"))
        Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("r-x------"))
        return try { Files.deleteIfExists(file) } catch (_: java.io.IOException) { false }
            finally { Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwx------")) }
    }

    private fun restoreWritable(root: Path) {
        Files.walk(root).use { paths ->
            paths.filter(Files::isDirectory).forEach { folder ->
                runCatching { Files.setPosixFilePermissions(folder, PosixFilePermission.values().toSet()) }
            }
        }
    }

    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("vpn-control-runtime-retire")
        try {
            block(root)
        } finally {
            restoreWritable(root)
            root.toFile().deleteRecursively()
        }
    }

    private companion object {
        /** The label the manager's retirement reports under on the owner's stderr. */
        const val CONNECTION_RUNTIME_REPORT_LABEL = "Connection runtime"
        const val KEY_BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
        const val KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n$KEY_BODY\n-----END OPENSSH PRIVATE KEY-----\n"
        val SETTINGS = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
            hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"))

        fun isWindows() = System.getProperty("os.name").startsWith("Windows")

        fun candidates(runtime: Path): List<String> = if (!Files.isDirectory(runtime)) emptyList() else
            Files.list(runtime).use { paths -> paths.map { it.fileName.toString() }.filter { it.startsWith("candidate-") }.sorted().toList() }
    }
}
