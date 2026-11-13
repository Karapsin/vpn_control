package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue

/**
 * Native run 584d9f4c-20c1-4e10-a485-4ae5f2c2b535 (Windows, package 2.2.17): a refresh through the SSH Routing
 * bootstrap (HOME_RELAY) answered OK and left `home-ssh-bootstrap-*` files in the workspace's runtime folder. The
 * bootstrap stopped its sing-box, deleted each file once and swallowed a refused deletion, while Windows refuses a
 * deletion for a while after the child was told to end: the child's handles (among them the log redirect, which the
 * JVM opens without delete sharing) close only as the process object ends, and a scanner may hold a fresh file.
 *
 * These tests drive the public download client with a stand-in for sing-box and refuse deletions the POSIX way: the
 * stand-in makes the runtime folder read-only and a watcher makes it writable again 0.4 s after the stand-in is gone.
 * The test itself listens on the configured port and answers the download as the bootstrap's proxy would.
 */
class DesktopHomeSshBootstrapCleanupTest {
    @Test fun deletionsRefusedUntilShortlyAfterTheBootstrapEndedLeaveNoBootstrapFile() {
        val outcome = download(Mode.REFUSE_UNTIL_AFTER_EXIT)
        assertEquals(BODY, outcome.body)
        assertEquals(emptyList(), outcome.leftAfterReturn, "bootstrap files left once the download returned")
        assertFalse(outcome.standInAliveAfterReturn, "the stand-in still ran once the download returned")
    }

    @Test fun aBootstrapThatIgnoresTerminationIsKilledAndAwaitedBeforeItsFilesAreDeleted() {
        val outcome = download(Mode.REFUSE_UNTIL_AFTER_EXIT_IGNORING_TERM)
        assertEquals(BODY, outcome.body)
        assertEquals(emptyList(), outcome.leftAfterReturn, "bootstrap files left once the download returned")
        assertFalse(outcome.standInAliveAfterReturn, "the stand-in still ran once the download returned")
    }

    @Test fun theConfigurationIsGoneOnceTheBootstrapListensAndNoLogIsWritten() {
        val outcome = download(Mode.PLAIN)
        assertEquals(BODY, outcome.body)
        val config = assertNotNull(outcome.configAtStart, "the stand-in found no configuration")
        // The configuration names the imported key by path and never holds key material.
        assertEquals(outcome.keyPath, config.privateKeyPath)
        assertFalse(config.inlineKey, "the ssh outbound carries an inline private_key")
        assertFalse(KEY_BODY in config.text, "key material in the bootstrap configuration")
        assertEquals("rw-------", config.permissions, "the bootstrap configuration is not owner-only")
        assertEquals(emptyList(), outcome.leftDuringDownload, "bootstrap files while sing-box carried the download")
        assertEquals(emptyList(), outcome.leftAfterReturn, "bootstrap files left once the download returned")
    }

    @Test fun aMissingSingBoxLeavesNoBootstrapFile() = fixture { root ->
        val runtime = root.resolve("workspace").resolve("runtime")
        val credentials = DesktopHomeSshCredentialStore(root.resolve("workspace")).also { it.importPrivateKey(KEY) }
        val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = StandIn(null), osNameOverride = "none")
        assumeTrue("a sing-box resolved from the environment or PATH", resolver.resolve() == null)
        val client = DesktopSubscriptionDownloadClient(stateProvider = { PersistedState(homeSshRouteSettings = SETTINGS) },
            credentialStore = credentials, bootstrapBaseDir = runtime, singBoxResolver = resolver)
        val failure = runCatching { runBlocking { client.fetch(URL, "") } }.exceptionOrNull()
        assertTrue(failure is IllegalStateException && failure.message == resolver.missingMessage(), "$failure")
        assertEquals(emptyList(), bootstrapFiles(runtime), "bootstrap files left without a sing-box")
    }

    private enum class Mode { PLAIN, REFUSE_UNTIL_AFTER_EXIT, REFUSE_UNTIL_AFTER_EXIT_IGNORING_TERM }

    private class ConfigAtStart(val text: String, val permissions: String, val privateKeyPath: String?, val inlineKey: Boolean)

    private class Outcome(
        val body: String?,
        val keyPath: String?,
        val configAtStart: ConfigAtStart?,
        val leftDuringDownload: List<String>?,
        val leftAfterReturn: List<String>,
        val standInAliveAfterReturn: Boolean,
    )

    private fun download(mode: Mode): Outcome {
        assumeFalse("POSIX permissions stand in for Windows' refusals", isWindows())
        assumeTrue("VPN_CONTROL_SING_BOX overrides the stand-in", System.getenv("VPN_CONTROL_SING_BOX").isNullOrBlank())
        var outcome: Outcome? = null
        fixture { root ->
            val workspace = root.resolve("workspace")
            val runtime = Files.createDirectories(workspace.resolve("runtime"))
            if (mode != Mode.PLAIN) assumeFalse("this account deletes in a read-only folder", deletesInReadOnlyFolder(root))
            val signal = Files.createDirectory(root.resolve("signal"))
            val credentials = DesktopHomeSshCredentialStore(workspace).also { it.importPrivateKey(KEY) }
            val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = StandIn(standIn(mode, signal)))
            assumeTrue("the stand-in did not resolve", resolver.resolve()?.path?.startsWith(runtime.resolve("tools")) == true)
            val client = DesktopSubscriptionDownloadClient(stateProvider = { PersistedState(homeSshRouteSettings = SETTINGS) },
                credentialStore = credentials, bootstrapBaseDir = runtime, singBoxResolver = resolver)
            val proxy = StandInProxy(signal, runtime)
            var pid: Long? = null
            try {
                val body = runBlocking { client.fetch(URL, "") }.body
                pid = proxy.pid
                outcome = Outcome(body, credentials.privateKeyPathOrNull(), proxy.config.get(), proxy.leftDuringDownload.get(),
                    bootstrapFiles(runtime), pid?.let { ProcessHandle.of(it).map(ProcessHandle::isAlive).orElse(false) } ?: false)
            } finally {
                proxy.close()
                (pid ?: proxy.pid)?.let { ProcessHandle.of(it).ifPresent(ProcessHandle::destroyForcibly) }
                Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwx------"))
            }
        }
        return checkNotNull(outcome)
    }

    /** Listens on the port the stand-in reports, answers the download and notes what the runtime folder holds then. */
    private inner class StandInProxy(private val signal: Path, private val runtime: Path) : AutoCloseable {
        val config = AtomicReference<ConfigAtStart?>()
        val leftDuringDownload = AtomicReference<List<String>?>()
        @Volatile var pid: Long? = null
        @Volatile private var server: ServerSocket? = null
        @Volatile private var closed = false
        private val worker = thread(name = "bootstrap-stand-in-proxy", isDaemon = true) { serve() }

        private fun serve() {
            val started = signal.resolve("started")
            val deadline = System.nanoTime() + 30_000_000_000L
            while (!Files.exists(started)) {
                if (closed || System.nanoTime() > deadline) return
                Thread.sleep(20)
            }
            val (standInPid, port) = Files.readString(started).trim().split(' ').map(String::toLong)
            pid = standInPid
            config.set(readConfig())
            val listener = ServerSocket(port.toInt(), 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
            server = listener
            while (!closed) {
                val socket = try { listener.accept() } catch (_: SocketException) { return }
                socket.use { answer(it) }
            }
        }

        private fun readConfig(): ConfigAtStart? {
            val file = Files.list(runtime).use { paths ->
                paths.filter { it.fileName.toString().let { name -> name.startsWith(PREFIX) && name.endsWith(".json") } }.toList()
            }.singleOrNull() ?: return null
            val text = Files.readString(file)
            val ssh = Json.parseToJsonElement(text).jsonObject.getValue("outbounds").jsonArray.map { it.jsonObject }
                .single { it["type"]?.jsonPrimitive?.content == "ssh" }
            return ConfigAtStart(text, PosixFilePermissions.toString(Files.getPosixFilePermissions(file)),
                ssh["private_key_path"]?.jsonPrimitive?.content, "private_key" in ssh)
        }

        /** The readiness probe closes at once; the download is one GET through this proxy. */
        private fun answer(socket: Socket) {
            socket.soTimeout = 10_000
            val head = StringBuilder()
            val input = socket.getInputStream()
            while (!head.endsWith("\r\n\r\n")) {
                val next = input.read()
                if (next < 0) return
                head.append(next.toChar())
            }
            leftDuringDownload.compareAndSet(null, bootstrapFiles(runtime))
            val body = BODY.toByteArray(StandardCharsets.US_ASCII)
            socket.getOutputStream().apply {
                write(("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.size}\r\n" +
                    "Connection: close\r\n\r\n").toByteArray(StandardCharsets.US_ASCII))
                write(body)
                flush()
            }
        }

        override fun close() {
            closed = true
            server?.close()
            worker.join(5_000)
        }
    }

    /** Serves the stand-in as the bundled sing-box of every platform, or nothing. */
    private class StandIn(private val bytes: ByteArray?) : ClassLoader(null) {
        override fun getResourceAsStream(name: String): InputStream? =
            bytes?.takeIf { name.startsWith("bin/") }?.let(::ByteArrayInputStream)
    }

    private fun standIn(mode: Mode, signal: Path): ByteArray {
        val refuse = if (mode == Mode.PLAIN) "" else """
            |dir=${'$'}(pwd)
            |chmod u-w "${'$'}dir"
            |( while kill -0 ${'$'}${'$'} 2>/dev/null; do sleep 0.05; done; sleep 0.4; chmod u+w "${'$'}dir" ) </dev/null >/dev/null 2>&1 &
            |""".trimMargin()
        val term = if (mode == Mode.REFUSE_UNTIL_AFTER_EXIT_IGNORING_TERM) "trap '' TERM\n" else ""
        val script = """
            |#!/bin/sh
            |# Stand-in for sing-box: run -c <config>. It reports its pid and port; the test listens there.
            |config="${'$'}3"
            |port=${'$'}(sed -n 's/.*"listen_port":\([0-9][0-9]*\).*/\1/p' "${'$'}config")
            |""".trimMargin() + "\n" + term + refuse + """
            |printf '%s %s\n' "${'$'}${'$'}" "${'$'}port" > "$signal/started.tmp" && mv "$signal/started.tmp" "$signal/started"
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

    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("vpn-control-bootstrap-cleanup")
        try {
            block(root)
        } finally {
            Files.walk(root).use { paths ->
                paths.filter(Files::isDirectory).forEach { folder ->
                    runCatching { Files.setPosixFilePermissions(folder, PosixFilePermission.values().toSet()) }
                }
            }
            root.toFile().deleteRecursively()
        }
    }

    private companion object {
        const val PREFIX = "home-ssh-bootstrap-"
        const val URL = "http://subscription.example.test/relay"
        const val BODY = "socks://127.0.0.1:1080#Fixture\n"
        const val KEY_BODY = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW"
        const val KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n$KEY_BODY\n-----END OPENSSH PRIVATE KEY-----\n"
        val SETTINGS = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
            hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBootstrapCleanupFixtureHostKey0000000000"))

        fun isWindows() = System.getProperty("os.name").startsWith("Windows")

        fun bootstrapFiles(runtime: Path): List<String> = if (!Files.isDirectory(runtime)) emptyList() else
            Files.list(runtime).use { paths -> paths.map { it.fileName.toString() }.filter { it.startsWith(PREFIX) }.sorted().toList() }
    }
}
