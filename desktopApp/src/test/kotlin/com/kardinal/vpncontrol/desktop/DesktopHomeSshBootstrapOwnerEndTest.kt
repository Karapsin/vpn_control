package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue

/**
 * Review of 1fe2ddab: the SSH Routing bootstrap was cleaned up only on its owner's own `finally`. Its sing-box holds an
 * authenticated SSH session to the home relay behind a loopback inbound without users, and its configuration names the
 * relay, so an owner that ended any other way (SIGTERM, End task or `taskkill /F`, SIGKILL, a crash) left the child
 * running, and, before readiness, the configuration in the runtime folder; no owner start ended or removed either.
 *
 * A child JVM ([DesktopHomeSshBootstrapOwnerProbe]) is the owner: it refreshes through the public download client with
 * a stand-in sing-box that reports its pid and port. The test is the bootstrap's proxy, or withholds it, and ends the
 * owner. A second child JVM is the next owner start, through the public factory under a selected workspace. POSIX only:
 * Windows ends the child with its job ([DesktopHomeSshBootstrapCleanupNativeTest]).
 */
class DesktopHomeSshBootstrapOwnerEndTest {
    @Test fun anOwnerShutDownBeforeTheBootstrapListensEndsItAndRemovesItsConfiguration() = owner { run ->
        run.start()
        run.signalShutdown()
        run.assertBootstrapEnded("after a shutdown before readiness")
    }

    @Test fun anOwnerShutDownDuringTheDownloadEndsTheBootstrap() = owner { run ->
        run.start()
        run.serveUntilTheRequest()
        run.signalShutdown()
        run.assertBootstrapEnded("after a shutdown during the download")
    }

    @Test fun theNextOwnerStartEndsABootstrapAKilledOwnerLeftAndRemovesItsConfiguration() = owner { run ->
        run.start()
        run.kill()
        // Nothing runs in a killed JVM: on POSIX its child and the configuration it had not yet read stay.
        assertTrue(run.standInAlive(), "the killed owner's stand-in ended by itself")
        assertTrue(run.bootstrapFiles().isNotEmpty(), "the configuration of a bootstrap not yet listening")
        val lines = run.nextOwnerStart()
        run.assertBootstrapEnded("after the next owner start")
        assertTrue(lines.any { it == "SSH Routing bootstrap: ended a sing-box an earlier owner left running (pid ${run.pid})" },
            lines.joinToString("\n"))
        assertTrue(lines.any { it.startsWith("SSH Routing bootstrap: removed home-ssh-bootstrap-") }, lines.joinToString("\n"))
    }

    private class Run(val root: Path) {
        val workspace: Path = root.resolve("workspace")
        val runtime: Path = workspace.resolve("runtime")
        private val signal: Path = Files.createDirectories(root.resolve("signal"))
        private var owner: Process? = null
        var pid: Long = 0
        private var port: Int = 0

        fun start() {
            val script = root.resolve("stand-in.sh")
            Files.write(script, standIn(signal))
            owner = java(DesktopHomeSshBootstrapOwnerProbe::class.java.name, "bootstrap", workspace.toString(), script.toString())
                .redirectOutput(root.resolve("owner.txt").toFile()).start()
            val started = signal.resolve("started")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
            while (!Files.exists(started)) {
                if (System.nanoTime() > deadline || owner?.isAlive != true) fail("the stand-in never started:\n${output()}")
                Thread.sleep(10)
            }
            val (standIn, listen) = Files.readString(started).trim().split(' ').map(String::toLong)
            pid = standIn
            port = listen.toInt()
        }

        /** Listens on the bootstrap's port, lets the readiness probe through and holds the download's request open. */
        fun serveUntilTheRequest() {
            val listener = ServerSocket(port, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
            listener.soTimeout = 30_000
            while (true) {
                val socket: Socket = listener.accept()
                socket.soTimeout = 2_000
                val first = runCatching { socket.getInputStream().read() }.getOrDefault(-1)
                if (first >= 0) {
                    held += socket
                    held += listener
                    return
                }
                socket.close()
            }
        }

        private val held = mutableListOf<AutoCloseable>()

        fun signalShutdown() {
            val process = checkNotNull(owner)
            process.destroy() // SIGTERM: the JVM runs its shutdown hooks.
            assertTrue(process.waitFor(60, TimeUnit.SECONDS), "the owner did not end:\n${output()}")
        }

        fun kill() {
            val process = checkNotNull(owner)
            process.destroyForcibly() // SIGKILL: no hook, no finally.
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "the owner did not end")
        }

        fun nextOwnerStart(): List<String> {
            val output = root.resolve("next-owner.txt")
            val process = java(DesktopHomeSshBootstrapOwnerProbe::class.java.name, "owner-start", workspace.toString())
                .redirectOutput(output.toFile()).start()
            val finished = process.waitFor(120, TimeUnit.SECONDS)
            if (!finished) process.destroyForcibly()
            val text = Files.readString(output)
            assertTrue(finished && process.exitValue() == 0 && "owner started" in text.lines(), "the next owner failed:\n$text")
            return text.lines()
        }

        fun standInAlive(): Boolean = ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)

        fun bootstrapFiles(): List<String> = if (!Files.isDirectory(runtime)) emptyList() else
            Files.list(runtime).use { paths ->
                paths.map { it.fileName.toString() }.filter { it.startsWith(DesktopHomeSshBootstrapProxy.FILE_PREFIX) }.sorted().toList()
            }

        fun assertBootstrapEnded(stage: String) {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (standInAlive() && System.nanoTime() < deadline) Thread.sleep(50)
            assertFalse(standInAlive(), "the bootstrap's sing-box still ran $stage:\n${output()}")
            assertEquals(emptyList(), bootstrapFiles(), "bootstrap files left $stage")
        }

        fun output(): String = runCatching { Files.readString(root.resolve("owner.txt")) }.getOrDefault("")

        fun close() {
            held.forEach { runCatching { it.close() } }
            owner?.let { if (it.isAlive) it.destroyForcibly() }
            if (pid != 0L) ProcessHandle.of(pid).ifPresent(ProcessHandle::destroyForcibly)
        }

        private fun java(vararg arguments: String): ProcessBuilder {
            val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
            val builder = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djava.awt.headless=true", "-Duser.home=${root.resolve("home")}", "-cp", classpath) + arguments)
                .redirectErrorStream(true)
            builder.environment().remove("VPN_CONTROL_SING_BOX")
            return builder
        }
    }

    private fun owner(block: (Run) -> Unit) {
        assumeFalse("POSIX: Windows ends the bootstrap with its job", System.getProperty("os.name").startsWith("Windows"))
        assumeTrue("VPN_CONTROL_SING_BOX overrides the stand-in", System.getenv("VPN_CONTROL_SING_BOX").isNullOrBlank())
        val root = Files.createTempDirectory("vpn-control-bootstrap-owner-end")
        val run = Run(root)
        try {
            block(run)
        } finally {
            run.close()
            root.toFile().deleteRecursively()
        }
    }

    private companion object {
        /** Stand-in for sing-box (`run -c <config>`): it reports its pid and port and runs until it is ended. */
        fun standIn(signal: Path): ByteArray = """
            |#!/bin/sh
            |config="${'$'}3"
            |port=${'$'}(sed -n 's/.*"listen_port":\([0-9][0-9]*\).*/\1/p' "${'$'}config")
            |printf '%s %s\n' "${'$'}${'$'}" "${'$'}port" > "$signal/started.tmp" && mv "$signal/started.tmp" "$signal/started"
            |while :; do sleep 0.1; done
            |""".trimMargin().toByteArray(StandardCharsets.US_ASCII)
    }
}

/** The owners of [DesktopHomeSshBootstrapOwnerEndTest]: a refresh through the bootstrap, or an owner start. */
object DesktopHomeSshBootstrapOwnerProbe {
    private const val KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"

    @JvmStatic fun main(arguments: Array<String>) {
        val workspace = Path.of(arguments[1])
        when (arguments[0]) {
            "bootstrap" -> {
                val bytes = Files.readAllBytes(Path.of(arguments[2]))
                val runtime = workspace.resolve("runtime")
                val credentials = DesktopHomeSshCredentialStore(workspace).also { it.importPrivateKey(KEY) }
                val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = object : ClassLoader(null) {
                    override fun getResourceAsStream(name: String): InputStream? =
                        if (name.startsWith("bin/")) ByteArrayInputStream(bytes) else null
                })
                val settings = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
                    hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBootstrapCleanupFixtureHostKey0000000000"))
                val client = DesktopSubscriptionDownloadClient(stateProvider = { PersistedState(homeSshRouteSettings = settings) },
                    credentialStore = credentials, bootstrapBaseDir = runtime, singBoxResolver = resolver)
                println(runCatching { runBlocking { client.fetch("http://subscription.example.test/relay", "") } }.exceptionOrNull())
                exitProcess(0)
            }
            "owner-start" -> {
                DesktopWorkspacePaths.configure(DesktopWorkspaceInvocation(emptyList(), workspace))
                DesktopAppServiceFactory.default()
                println("owner started")
                System.out.flush()
                exitProcess(0)
            }
            else -> exitProcess(2)
        }
    }
}
