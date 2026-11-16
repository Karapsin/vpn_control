package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.sun.jna.Platform
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue

/**
 * Native run 584d9f4c-20c1-4e10-a485-4ae5f2c2b535: `home-ssh-bootstrap-*` files were left after a refresh through
 * the SSH Routing bootstrap. The OS rule behind it, shown on Windows: a file the JVM opened for writing (as it opens a
 * child's output redirect, which the child inherits) refuses deletion until that handle closes, and one refused
 * deletion was all the bootstrap tried.
 */
class DesktopHomeSshBootstrapCleanupNativeTest {
    private fun fixture(block: (Path) -> Unit) {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("bootstrap-cleanup-native-東京")
        try { block(root) }
        finally { root.toFile().deleteRecursively() }
    }

    /** The unfixed bootstrap's log: the JVM's redirect handle shares read and write, never delete. */
    @Test fun nativeAFileOpenForWritingByTheJvmRefusesDeletionUntilItCloses() = fixture { root ->
        val log = Files.createTempFile(root, "home-ssh-bootstrap-", ".log")
        FileOutputStream(log.toFile()).use { output ->
            output.write("sing-box".toByteArray())
            val refused = assertFailsWith<FileSystemException> { Files.delete(log) }
            assertTrue(refused !is java.nio.file.NoSuchFileException, "$refused")
            runCatching { Files.deleteIfExists(log) } // the unfixed cleanup: one attempt, swallowed
            assertTrue(Files.exists(log), "the refused deletion removed the file")
        }
        Files.delete(log)
    }

    @Test fun nativeTheCleanupRemovesAFileOnceItsHolderLetsGo() = fixture { root ->
        val config = Files.writeString(root.resolve("home-ssh-bootstrap-1.json"), "{}")
        val holder = FileOutputStream(config.toFile(), true)
        val reports = Collections.synchronizedList(mutableListOf<String>())
        val releaser = thread { Thread.sleep(300); holder.close() }
        try {
            assertNull(DesktopBootstrapCleanup(report = { reports += it }).remove(config))
        } finally {
            releaser.join()
            holder.close()
        }
        assertFalse(Files.exists(config))
        assertEquals(emptyList(), reports)
    }

    @Test fun nativeAFileHeldPastTheBoundIsReportedByLeafAndRefusal() = fixture { root ->
        val config = Files.writeString(root.resolve("home-ssh-bootstrap-2.json"), "{}")
        val reports = Collections.synchronizedList(mutableListOf<String>())
        FileOutputStream(config.toFile(), true).use {
            DesktopBootstrapCleanup(report = { reports += it }, retryDelaysMillis = listOf(10L, 10L)).finish(null, listOf(config))
        }
        assertEquals(1, reports.size, "$reports")
        assertTrue(reports.single().startsWith("SSH Routing bootstrap: home-ssh-bootstrap-2.json was not removed after 3 attempts (" +
            "FileSystemException: "), reports.single())
        assertFalse(root.toString() in reports.single(), "the report names the folder")
        Files.delete(config)
    }

    /**
     * The whole bootstrap on Windows with a real child: its configuration is held without delete sharing until a
     * moment after the child's process object has ended, yet nothing is left once the download returned.
     */
    @Test fun nativeTheBootstrapLeavesNothingOnceItsChildAndTheConfigurationsHolderAreGone() = fixture { root ->
        val runtime = root.resolve("runtime")
        val credentials = DesktopHomeSshCredentialStore(root).also {
            it.importPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfixturefixturefixture\n-----END OPENSSH PRIVATE KEY-----\n")
        }
        val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = object : ClassLoader(null) {
            override fun getResourceAsStream(name: String): InputStream? = if (name.startsWith("bin/")) "stand-in".byteInputStream() else null
        })
        val reports = Collections.synchronizedList(mutableListOf<String>())
        var child: Process? = null
        var listener: ServerSocket? = null
        var holder: FileOutputStream? = null
        try {
            val proxy = DesktopHomeSshBootstrapProxy(runtime, resolver, launch = { command, directory ->
                val config = Path.of(command[3])
                val port = Regex("\"listen_port\":(\\d+)").find(Files.readString(config))!!.groupValues[1].toInt()
                val socket = ServerSocket(port, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                listener = socket
                thread(isDaemon = true) { while (true) { try { socket.accept().close() } catch (_: SocketException) { break } } }
                // A real child that lives until it is ended, with the product's own launcher (output discarded).
                val started = launchBootstrapRuntime(listOf("ping.exe", "-n", "60", "127.0.0.1"), directory)
                child = started
                val held = FileOutputStream(config.toFile(), true)
                holder = held
                started.onExit().thenRun { Thread.sleep(300); held.close() }
                started
            }, cleanup = DesktopBootstrapCleanup(report = { reports += it }))
            val settings = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
                hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBootstrapCleanupFixtureHostKey0000000000"))
            val during = runBlocking {
                proxy.useProxy(HomeSshRouteRuntimeOptions(settings, checkNotNull(credentials.privateKeyPathOrNull()))) {
                    Files.list(runtime).use { paths -> paths.map { it.fileName.toString() }.filter { it.startsWith("home-ssh-bootstrap-") }.toList() }
                }
            }
            assertEquals(1, during.size, "the held configuration refused its early deletion: $during")
            assertFalse(checkNotNull(child).isAlive, "the child still ran once the download returned")
            assertEquals(emptyList(), Files.list(runtime).use { paths ->
                paths.map { it.fileName.toString() }.filter { it.startsWith("home-ssh-bootstrap-") }.toList() })
            assertEquals(emptyList(), reports)
        } finally {
            child?.destroyForcibly()
            holder?.close()
            listener?.close()
        }
    }

    /**
     * Review of 1fe2ddab: the bootstrap's sing-box (an authenticated SSH session behind a loopback inbound without users)
     * outlived an owner ended by End task or `taskkill /F`, since only the owner's own `finally` stopped it. A child JVM
     * starts a real child with the product's launcher and ties it to its lifetime; TerminateProcess on that JVM (no
     * `finally`, no shutdown hook) must take the child with it.
     */
    @Test fun nativeAnOwnerEndedByTerminateProcessTakesItsTiedBootstrapChildWithIt() = fixture { root ->
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        val owner = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java.exe").toString(), "-cp", classpath,
            DesktopTiedBootstrapOwner::class.java.name, root.toString())
            .redirectErrorStream(true).redirectOutput(root.resolve("owner.txt").toFile()).start()
        var child: ProcessHandle? = null
        try {
            val pidFile = root.resolve("child.pid")
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(60)
            while (!Files.exists(pidFile)) {
                assertTrue(owner.isAlive && System.nanoTime() < deadline, "the owner never tied its child: " +
                    runCatching { Files.readString(root.resolve("owner.txt")) }.getOrDefault(""))
                Thread.sleep(20)
            }
            child = ProcessHandle.of(Files.readString(pidFile).trim().toLong()).orElseThrow()
            owner.destroyForcibly() // TerminateProcess.
            assertTrue(owner.waitFor(30, java.util.concurrent.TimeUnit.SECONDS))
            val ended = runCatching { child.onExit().get(10, java.util.concurrent.TimeUnit.SECONDS) }.isSuccess
            assertTrue(ended && !child.isAlive, "the tied child outlived its owner")
        } finally {
            owner.destroyForcibly()
            child?.destroyForcibly()
        }
    }
}

/** The owner of [DesktopHomeSshBootstrapCleanupNativeTest.nativeAnOwnerEndedByTerminateProcessTakesItsTiedBootstrapChildWithIt]. */
object DesktopTiedBootstrapOwner {
    @JvmStatic fun main(arguments: Array<String>) {
        val directory = Path.of(arguments.single())
        val child = launchBootstrapRuntime(listOf("ping.exe", "-n", "120", "127.0.0.1"), directory)
        checkNotNull(tieToOwnerLifetime(child)) { "no tie on Windows" }
        val temporary = directory.resolve("child.pid.tmp")
        Files.writeString(temporary, child.pid().toString())
        Files.move(temporary, directory.resolve("child.pid"))
        Thread.sleep(120_000)
    }
}
