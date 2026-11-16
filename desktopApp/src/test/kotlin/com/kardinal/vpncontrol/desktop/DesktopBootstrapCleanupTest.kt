package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.HomeSshRouteRuntimeOptions
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import java.nio.file.AccessDeniedException
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.Path
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** The bootstrap's cleanup decisions over fake processes and file systems (native run 584d9f4c, `bootstrap-files-left`). */
class DesktopBootstrapCleanupTest {
    private val path: Path = Path.of("runtime-folder-that-is-never-reported", "home-ssh-bootstrap-123.json")
    private val sharing = "The process cannot access the file because it is being used by another process"

    /** Refuses the first [refused] deletions the way Java reports a Windows sharing violation, then deletes. */
    private class Deletions(private val refused: Int, private val failure: (Path) -> IOException) {
        val calls = Collections.synchronizedList(mutableListOf<Path>())
        fun delete(path: Path) {
            calls.add(path) // not +=: a Path is an Iterable<Path>
            if (calls.size <= refused) throw failure(path)
        }
    }

    private class Recorder {
        val sleeps = Collections.synchronizedList(mutableListOf<Long>())
        val reports = Collections.synchronizedList(mutableListOf<String>())
    }

    /**
     * A child whose exit code is set as soon as it is asked to end (when [endsOnRequest]) or killed, as Windows may
     * set it before the child's handles are closed; its process object ends only at [release], which the child does
     * itself [releaseMillis] after the request or at once when killed, or the test does.
     */
    private class FakeChild(private val endsOnRequest: Boolean = true, private val releaseMillis: Long? = null) : Process() {
        val events = Collections.synchronizedList(mutableListOf<String>())
        private val processObject = CountDownLatch(1)
        @Volatile private var exitCode: Int? = null
        override fun getOutputStream(): OutputStream = OutputStream.nullOutputStream()
        override fun getInputStream(): InputStream = InputStream.nullInputStream()
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun waitFor(): Int {
            processObject.await()
            return checkNotNull(exitCode)
        }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean {
            events += "waitFor($timeout)"
            return exitCode != null
        }
        override fun exitValue(): Int = exitCode ?: throw IllegalThreadStateException("running")
        override fun isAlive(): Boolean = exitCode == null
        override fun destroy() {
            events += "destroy"
            if (!endsOnRequest) return
            exitCode = 1
            releaseMillis?.let { millis -> thread(isDaemon = true) { Thread.sleep(millis); release() } }
        }
        override fun destroyForcibly(): Process {
            events += "destroyForcibly"
            exitCode = 137
            if (releaseMillis != null) release()
            return this
        }
        fun release() {
            if (processObject.count == 0L) return
            events += "released"
            processObject.countDown()
        }
        val released get() = processObject.count == 0L
    }

    private fun cleanup(deletions: Deletions, recorder: Recorder, exitMillis: Long = 5_000) = DesktopBootstrapCleanup(
        delete = deletions::delete, sleep = { recorder.sleeps += it }, report = { recorder.reports += it },
        graceMillis = 2_000, exitMillis = exitMillis)

    @Test fun aDeletionRefusedThreeTimesIsRetriedWithBackoffAndNotReported() {
        val deletions = Deletions(3) { FileSystemException(it.toString(), null, sharing) }
        val recorder = Recorder()
        assertNull(cleanup(deletions, recorder).remove(path))
        assertEquals(4, deletions.calls.size)
        assertEquals(listOf(25L, 50L, 100L), recorder.sleeps)
        assertEquals(emptyList(), recorder.reports)
    }

    @Test fun aDeletePendingNameAnsweringAccessDeniedIsRetriedToo() {
        val deletions = Deletions(2) { AccessDeniedException(it.toString()) }
        val recorder = Recorder()
        assertNull(cleanup(deletions, recorder).remove(path))
        assertEquals(3, deletions.calls.size)
    }

    @Test fun aDeletionRefusedEveryTimeEndsAfterEightAttemptsAndIsReportedWithoutItsFolder() {
        val deletions = Deletions(Int.MAX_VALUE) { FileSystemException(it.toString(), null, sharing) }
        val recorder = Recorder()
        cleanup(deletions, recorder).finish(null, listOf(path))
        assertEquals(8, deletions.calls.size)
        assertEquals(listOf(25L, 50L, 100L, 200L, 400L, 800L, 1_600L), recorder.sleeps)
        assertEquals(3_175L, recorder.sleeps.sum(), "the bound of one file")
        assertEquals(listOf("SSH Routing bootstrap: home-ssh-bootstrap-123.json was not removed after 8 attempts " +
            "(FileSystemException: $sharing)"), recorder.reports)
        assertFalse(recorder.reports.single().contains("runtime-folder-that-is-never-reported"))
    }

    /** Without POSIX delete semantics a deletion succeeds while another handle is open, and the name stays listed. */
    @Test fun aNameStillListedAfterItsDeletionIsAwaitedLikeARefusal() {
        val deletions = Deletions(0) { IOException() }
        val listings = AtomicInteger(2)
        val recorder = Recorder()
        val cleanup = DesktopBootstrapCleanup(delete = deletions::delete, gone = { listings.getAndDecrement() <= 0 },
            sleep = { recorder.sleeps += it }, report = { recorder.reports += it })
        assertNull(cleanup.remove(path))
        assertEquals(3, deletions.calls.size)
        assertEquals(listOf(25L, 50L), recorder.sleeps)
    }

    @Test fun aNameListedPastTheBoundIsReported() {
        val deletions = Deletions(0) { IOException() }
        val recorder = Recorder()
        DesktopBootstrapCleanup(delete = deletions::delete, gone = { false }, sleep = { recorder.sleeps += it },
            report = { recorder.reports += it }).finish(null, listOf(path))
        assertEquals(8, deletions.calls.size)
        assertEquals(listOf("SSH Routing bootstrap: home-ssh-bootstrap-123.json was not removed after 8 attempts " +
            "(FileSystemException: still listed after its deletion)"), recorder.reports)
    }

    @Test fun anErrorThatTimeCannotEndIsReportedAtOnce() {
        val deletions = Deletions(Int.MAX_VALUE) { IOException("device error at $it") }
        val recorder = Recorder()
        cleanup(deletions, recorder).finish(null, listOf(path))
        assertEquals(1, deletions.calls.size)
        assertEquals(emptyList(), recorder.sleeps)
        assertEquals(listOf("SSH Routing bootstrap: home-ssh-bootstrap-123.json was not removed after 1 attempt (IOException)"),
            recorder.reports)
    }

    @Test fun theEarlyDeletionNeverReportsARefusal() {
        val deletions = Deletions(1) { FileSystemException(it.toString(), null, sharing) }
        val recorder = Recorder()
        val cleanup = cleanup(deletions, recorder)
        cleanup.deleteNow(path)
        cleanup.finish(null, listOf(path))
        assertEquals(2, deletions.calls.size)
        assertEquals(emptyList(), recorder.reports)
    }

    /** The exit code is set at the request, but no deletion runs before the child's process object has ended. */
    @Test fun theChildIsAwaitedByItsProcessObjectBeforeAnyDeletion() {
        val child = FakeChild(releaseMillis = 300)
        val deletions = Deletions(0) { FileSystemException(it.toString(), null, sharing) }
        val releasedAtDeletion = Collections.synchronizedList(mutableListOf<Boolean>())
        val recorder = Recorder()
        val cleanup = DesktopBootstrapCleanup(delete = { releasedAtDeletion += child.released; deletions.delete(it) },
            sleep = { recorder.sleeps += it }, report = { recorder.reports += it })
        cleanup.finish(child, listOf(path))
        assertEquals(listOf("destroy", "waitFor(2000)"), child.events.take(2), "asked to end, then the grace")
        assertTrue("destroyForcibly" !in child.events, "an exit code set at the request is no reason to kill")
        assertEquals(listOf(true), releasedAtDeletion.toList(), "a deletion ran before the process object ended")
        assertEquals(emptyList(), recorder.reports)
    }

    @Test fun aChildThatIgnoresTheRequestIsKilledAfterTheGrace() {
        val child = FakeChild(endsOnRequest = false, releaseMillis = 0)
        val recorder = Recorder()
        cleanup(Deletions(0) { IOException() }, recorder).finish(child, listOf(path))
        assertEquals(listOf("destroy", "waitFor(2000)", "destroyForcibly", "released"), child.events.toList())
        assertEquals(emptyList(), recorder.reports)
    }

    @Test fun aChildWhoseProcessObjectOutlivesTheBoundIsReportedAndItsFilesAreStillDeleted() {
        val child = FakeChild()
        val deletions = Deletions(0) { IOException() }
        val recorder = Recorder()
        try {
            cleanup(deletions, recorder, exitMillis = 200).finish(child, listOf(path))
        } finally {
            child.release()
        }
        assertEquals(listOf(path), deletions.calls.toList())
        assertEquals(listOf("SSH Routing bootstrap: sing-box was not seen to end within 200 ms of being stopped"), recorder.reports)
    }

    @Test fun aReportThatFailsNeverEscapesTheCleanup() {
        val deletions = Deletions(Int.MAX_VALUE) { FileSystemException(it.toString(), null, sharing) }
        DesktopBootstrapCleanup(delete = deletions::delete, sleep = {}, report = { error("stderr is gone") }).finish(null, listOf(path))
        assertEquals(8, deletions.calls.size)
    }

    @Test fun theBootstrapRuntimeKeepsNoOutputOnDisk() {
        val folder = Files.createTempDirectory("vpn-control-bootstrap-output")
        try {
            val command = if (System.getProperty("os.name").startsWith("Windows")) listOf("cmd.exe", "/c", "echo out & echo err 1>&2")
                else listOf("/bin/sh", "-c", "echo out; echo err >&2")
            val process = launchBootstrapRuntime(command, folder)
            assertTrue(process.waitFor(30, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue())
            assertEquals(-1, process.inputStream.read(), "the output reached the JVM")
            assertEquals(emptyList(), Files.list(folder).use { it.toList() })
        } finally {
            folder.toFile().deleteRecursively()
        }
    }

    /** The configuration is deleted once sing-box listens, before the download, and the child is ended after it. */
    @Test fun theBootstrapDeletesItsConfigurationBeforeTheDownloadAndEndsTheChildAfterIt() {
        val root = Files.createTempDirectory("vpn-control-bootstrap-proxy")
        val child = FakeChild(releaseMillis = 50)
        var listener: ServerSocket? = null
        try {
            val runtime = root.resolve("runtime")
            val credentials = DesktopHomeSshCredentialStore(root).also {
                it.importPrivateKey("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfixturefixturefixture\n-----END OPENSSH PRIVATE KEY-----\n")
            }
            val resolver = DesktopSingBoxResolver(runtime.resolve("tools"), classLoader = object : ClassLoader(null) {
                override fun getResourceAsStream(name: String): InputStream? =
                    if (name.startsWith("bin/")) "stand-in".byteInputStream() else null
            })
            val launched = mutableListOf<List<String>>()
            val recorder = Recorder()
            val proxy = DesktopHomeSshBootstrapProxy(runtime, resolver, launch = { command, directory ->
                launched += command
                assertEquals(runtime, directory)
                val port = Regex("\"listen_port\":(\\d+)").find(Files.readString(Path.of(command[3])))!!.groupValues[1].toInt()
                val socket = ServerSocket(port, 50, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)))
                listener = socket
                thread(isDaemon = true) {
                    while (true) { try { socket.accept().close() } catch (_: SocketException) { break } }
                }
                child
            }, cleanup = DesktopBootstrapCleanup(sleep = { recorder.sleeps += it }, report = { recorder.reports += it }),
                // FakeChild is no operating-system process (Process.pid() throws UnsupportedOperationException), so
                // the platform tie would only fail on it on Windows: record the tie instead, on every platform.
                tie = { process ->
                    assertSame(child, process)
                    child.events += "tied"
                    AutoCloseable { child.events += "untied" }
                })
            val settings = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
                hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBootstrapCleanupFixtureHostKey0000000000"))
            val during = runBlocking {
                proxy.useProxy(HomeSshRouteRuntimeOptions(settings, checkNotNull(credentials.privateKeyPathOrNull()))) {
                    Files.list(runtime).use { paths -> paths.map { it.fileName.toString() }.filter { it.startsWith("home-ssh-bootstrap-") }.toList() }
                }
            }
            assertEquals(emptyList(), during, "bootstrap files while the download ran")
            assertEquals("run", launched.single()[1])
            assertTrue(child.events.containsAll(listOf("destroy", "released")))
            assertEquals(listOf("tied", "destroy", "released", "untied"),
                child.events.filter { it in setOf("tied", "destroy", "released", "untied") },
                "the child was not tied once at its start and untied after it ended")
            assertEquals(emptyList(), recorder.reports)
            assertEquals(emptyList(), Files.list(runtime).use { paths ->
                paths.map { it.fileName.toString() }.filter { it.startsWith("home-ssh-bootstrap-") }.toList() })
        } finally {
            child.release()
            listener?.close()
            root.toFile().deleteRecursively()
        }
    }

    @Test fun theDefaultBoundIsEightAttemptsOverAboutThreeSeconds() {
        assertEquals(listOf(25L, 50L, 100L, 200L, 400L, 800L, 1_600L), DesktopBootstrapCleanup.RETRY_DELAYS_MILLIS)
    }
}
