package com.kardinal.vpncontrol.desktop

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.util.Optional
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.stream.Stream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The owner-lifetime seams behind the review of 1fe2ddab: a short-lived runtime finishes once, whoever comes first;
 * a JVM shutdown finishes every live one and admits no new one; a child the owner could not tie to its lifetime is
 * reported; and the owner-start reaper ends only a sing-box running one of its own folder's short-lived configurations
 * and removes only files with their prefixes, never the main runtime's.
 */
class DesktopShortLivedRuntimeTest {
    @Test fun aShutdownFinishesEveryLiveRuntimeAndAdmitsNoNewOne() = fixture { folder ->
        val hooks = mutableListOf<Thread>()
        val children = DesktopShortLivedRuntimes(registerHook = { hooks += it })
        val child = Child()
        val reports = mutableListOf<String>()
        val runtime = DesktopShortLivedRuntime(cleanup(reports), tie = { null })
        val registration = children.register(runtime)
        val file = runtime.createFile(folder, DesktopHomeSshBootstrapProxy.FILE_PREFIX, ".json")
        runtime.start { child }
        assertEquals(1, hooks.size, "one hook, installed with the first runtime")
        hooks.single().run()
        assertTrue(child.destroyed && !child.isAlive, "the child still ran after the shutdown")
        assertFalse(Files.exists(file), "the configuration stayed after the shutdown")
        assertEquals(emptyList(), reports)
        assertFailsWith<IllegalStateException> { children.register(DesktopShortLivedRuntime(cleanup(reports), tie = { null })) }
        assertFailsWith<IllegalStateException> { runtime.createFile(folder, "late-", ".json") }
        assertFailsWith<IllegalStateException> { runtime.start { Child() } }
        registration.close()
    }

    @Test fun aRuntimeFinishesOnceWhoeverComesFirstAndClosesItsTieAfterTheChild() = fixture { folder ->
        val order = mutableListOf<String>()
        val child = Child(onDestroy = { order += "child" })
        val runtime = DesktopShortLivedRuntime(cleanup(mutableListOf()), tie = { AutoCloseable { order += "tie" } })
        val result = runtime.within(DesktopShortLivedRuntimes(registerHook = {})) {
            it.createFile(folder, "validate-fixture-", ".json")
            it.start { child }
            it.finish() // A shutdown that came first.
            "done"
        }
        assertEquals("done", result)
        assertEquals(listOf("child", "tie"), order, "finished twice, or the tie closed before the child ended")
        assertEquals(emptyList(), Files.list(folder).use { it.toList() })
    }

    @Test fun aChildThatCannotBeTiedToTheOwnerIsReportedAndStillCarriesItsWork() = fixture { folder ->
        val reports = mutableListOf<String>()
        val runtime = DesktopShortLivedRuntime(cleanup(reports, label = DIRECT_PROBE_LABEL), tie = { throw IOException("refused") })
        val child = Child()
        runtime.within(DesktopShortLivedRuntimes(registerHook = {})) { assertEquals(child, it.start { child }) }
        assertEquals(listOf("Direct probe: sing-box is not tied to the owner's lifetime (IOException)"), reports)
        assertTrue(child.destroyed)
    }

    @Test fun theOwnerStartReaperEndsOnlyItsFoldersShortLivedRuntimesAndRemovesOnlyTheirFiles() = fixture { root ->
        val folder = Files.createDirectories(root.resolve("runtime"))
        val other = Files.createDirectories(root.resolve("other"))
        val me = ProcessHandle.current().info().user().orElse(null)
        fun config(directory: Path, name: String) = directory.resolve(name).toString()
        val bootstrap = Handle(101, listOf("/tools/sing-box", "run", "-c", config(folder, "home-ssh-bootstrap-1.json")), me)
        val viaDots = Handle(102, listOf("/tools/sing-box", "run", "-c", "$folder/../runtime/home-ssh-bootstrap-2.json"), me)
        val untouched = listOf(
            Handle(201, listOf("/tools/sing-box", "run", "-c", config(folder, "runtime-sing-box-vpn.json")), me),
            Handle(202, listOf("/tools/sing-box", "run", "-c", config(other, "home-ssh-bootstrap-3.json")), me),
            Handle(203, listOf("/tools/sing-box", "run", "-c", config(folder, "home-ssh-bootstrap-4.log")), me),
            Handle(204, listOf("/tools/sing-box", "check", "-c", config(folder, "home-ssh-bootstrap-5.json")), me),
            Handle(205, null, me),
            Handle(206, listOf("/tools/sing-box", "run", "-c", config(folder, "home-ssh-bootstrap-6.json")), "someone-else"),
            Handle(207, listOf("/tools/sing-box", "run", "-c", config(folder, "candidate-7.json")), me),
            Handle(ProcessHandle.current().pid(), listOf("run", "-c", config(folder, "home-ssh-bootstrap-8.json")), me),
        )
        for (name in listOf("home-ssh-bootstrap-1.json", "home-ssh-bootstrap-2.log", "runtime-sing-box-vpn.json", "candidate-7.json",
            "runtime-sing-box.log")) Files.writeString(folder.resolve(name), "{}")
        Files.createDirectories(folder.resolve("home-ssh-bootstrap-dir"))
        val reports = mutableListOf<String>()
        reapStaleShortLivedRuntimes(folder, listOf(DesktopHomeSshBootstrapProxy.FILE_PREFIX), cleanup(reports),
            processes = { listOf(bootstrap, viaDots) + untouched })
        assertTrue(bootstrap.destroyed && viaDots.destroyed, "a stale bootstrap still ran")
        if (me != null) assertFalse(untouched.any { it.destroyed }, "ended: ${untouched.filter { it.destroyed }.map { it.pid() }}")
        else assertFalse(untouched.filter { it.pid() != 206L }.any { it.destroyed })
        assertEquals(listOf("candidate-7.json", "home-ssh-bootstrap-dir", "runtime-sing-box-vpn.json", "runtime-sing-box.log"),
            Files.list(folder).use { paths -> paths.map { it.fileName.toString() }.sorted().toList() })
        assertEquals(listOf(
            "SSH Routing bootstrap: ended a sing-box an earlier owner left running (pid 101)",
            "SSH Routing bootstrap: ended a sing-box an earlier owner left running (pid 102)",
            "SSH Routing bootstrap: removed home-ssh-bootstrap-1.json, which an earlier owner left",
            "SSH Routing bootstrap: removed home-ssh-bootstrap-2.log, which an earlier owner left",
        ), reports)
    }

    @Test fun aStaleSingBoxThatIgnoresTerminationIsKilledAndOneThatOutlivesTheKillIsReported() = fixture { folder ->
        val args = listOf("run", "-c", folder.resolve("home-ssh-bootstrap-1.json").toString())
        val stubborn = Handle(301, args, null, endsOnDestroy = false)
        val immortal = Handle(302, args, null, endsOnDestroy = false, endsOnKill = false)
        val reports = mutableListOf<String>()
        reapStaleShortLivedRuntimes(folder, listOf(DesktopHomeSshBootstrapProxy.FILE_PREFIX), cleanup(reports),
            processes = { listOf(stubborn, immortal) })
        assertTrue(stubborn.killed && !stubborn.isAlive)
        assertEquals(listOf(
            "SSH Routing bootstrap: ended a sing-box an earlier owner left running (pid 301)",
            "SSH Routing bootstrap: a sing-box an earlier owner left running was not seen to end (pid 302)",
        ), reports)
    }

    @Test fun theOwnerStartReapsTheValidationFolderToo() = fixture { root ->
        val runtime = Files.createDirectories(root.resolve("runtime"))
        val validation = Files.createDirectories(root.resolve("validation"))
        Files.writeString(runtime.resolve("home-ssh-bootstrap-1.json"), "{}")
        for (name in listOf("validate-fixture-1.json", "validate-fixture-1.log", "direct-probe-2.json", "vpn-control-probe-sing-box")) {
            Files.writeString(validation.resolve(name), "{}")
        }
        reapShortLivedRuntimesAtOwnerStart(runtime, validation)
        assertEquals(emptyList(), Files.list(runtime).use { it.toList() })
        assertEquals(listOf("vpn-control-probe-sing-box"), Files.list(validation).use { paths -> paths.map { it.fileName.toString() }.toList() })
    }

    private fun cleanup(reports: MutableList<String>, label: String = "SSH Routing bootstrap") = DesktopBootstrapCleanup(
        sleep = {}, report = { reports += it }, graceMillis = 50, exitMillis = 200, label = label)

    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("vpn-control-short-lived-runtime")
        try {
            block(root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private class Child(private val onDestroy: () -> Unit = {}) : Process() {
        @Volatile var destroyed = false
        @Volatile private var exitCode: Int? = null
        override fun getOutputStream(): OutputStream = OutputStream.nullOutputStream()
        override fun getInputStream(): InputStream = InputStream.nullInputStream()
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun waitFor(): Int {
            while (exitCode == null) Thread.sleep(5)
            return exitCode!!
        }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = exitCode != null
        override fun exitValue(): Int = exitCode ?: throw IllegalThreadStateException("running")
        override fun isAlive(): Boolean = exitCode == null
        override fun destroy() {
            if (!destroyed) onDestroy()
            destroyed = true
            exitCode = 143
        }
        override fun pid(): Long = 4242
    }

    /** A process of the system as the reaper sees it: its pid, arguments and user. */
    private class Handle(
        private val id: Long,
        private val arguments: List<String>?,
        private val user: String?,
        private val endsOnDestroy: Boolean = true,
        private val endsOnKill: Boolean = true,
    ) : ProcessHandle {
        @Volatile var destroyed = false
        @Volatile var killed = false
        @Volatile private var alive = true
        private val exit = CompletableFuture<ProcessHandle>()

        override fun pid(): Long = id
        override fun parent(): Optional<ProcessHandle> = Optional.empty()
        override fun children(): Stream<ProcessHandle> = Stream.empty()
        override fun descendants(): Stream<ProcessHandle> = Stream.empty()
        override fun info(): ProcessHandle.Info = object : ProcessHandle.Info {
            override fun command(): Optional<String> = Optional.ofNullable(arguments?.firstOrNull())
            override fun commandLine(): Optional<String> = Optional.empty()
            override fun arguments(): Optional<Array<String>> = Optional.ofNullable(arguments?.toTypedArray())
            override fun startInstant(): Optional<Instant> = Optional.empty()
            override fun totalCpuDuration(): Optional<Duration> = Optional.empty()
            override fun user(): Optional<String> = Optional.ofNullable(user)
        }
        override fun onExit(): CompletableFuture<ProcessHandle> = exit
        override fun supportsNormalTermination(): Boolean = true
        override fun destroy(): Boolean {
            destroyed = true
            if (endsOnDestroy) end()
            return true
        }
        override fun destroyForcibly(): Boolean {
            destroyed = true
            killed = true
            if (endsOnKill) end()
            return true
        }
        override fun isAlive(): Boolean = alive
        override fun compareTo(other: ProcessHandle): Int = id.compareTo(other.pid())
        private fun end() {
            alive = false
            exit.complete(this)
        }
    }
}
