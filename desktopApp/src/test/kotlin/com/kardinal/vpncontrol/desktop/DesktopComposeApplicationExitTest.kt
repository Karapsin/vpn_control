package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * This is a real product-runner child JVM. It creates no Window, app workspace, owner, or runtime.
 */
class DesktopComposeApplicationExitTest {
    @Test
    fun frontendProcessLifecycleCleansUpBeforeExitAndPreservesBothFailures() {
        val events = mutableListOf<String>()
        val primary = IllegalStateException("frontend")
        val secondary = IllegalArgumentException("teardown")
        val thrown = assertFailsWith<IllegalStateException> {
            finishDesktopFrontendProcess(
                runFrontend = { events += "run"; throw primary },
                teardown = { events += "teardown"; throw secondary },
                reportFailure = { events += "report"; assertSame(primary, it) },
                terminate = { code -> events += "exit:$code" },
            )
        }
        assertSame(primary, thrown)
        assertEquals(listOf(secondary), primary.suppressed.toList())
        assertEquals(listOf("run", "teardown", "report", "exit:1"), events)
    }

    @Test
    fun frontendProcessLifecycleExitsNormallyAfterCleanup() {
        val events = mutableListOf<String>()
        finishDesktopFrontendProcess(
            runFrontend = { events += "run" }, teardown = { events += "teardown" },
            reportFailure = { error("Unexpected failure: $it") }, terminate = { code -> events += "exit:$code" },
        )
        assertEquals(listOf("run", "teardown", "exit:0"), events)
    }

    @Test
    fun productFrontendRunnerReturnsThroughTheOuterFinally() {
        val directory = Files.createTempDirectory("vpn-compose-application-exit")
        try {
            val sentinel = directory.resolve("finally")
            val output = runChild(sentinel)
            assertTrue(Files.exists(sentinel),
                "The product frontend runner must return through Main's teardown finally. Child output: $output")
            assertEquals("finally", Files.readString(sentinel))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private fun runChild(sentinel: Path): String {
        val javaName = if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java"
        val java = Path.of(System.getProperty("java.home"), "bin", javaName).toString()
        val classpath = DesktopJvmCliTestBootstrap.classpath(
            requireNotNull(System.getProperty("vpnControl.test.mainClasspath")),
        )
        val output = sentinel.resolveSibling("child.log")
        val phase = sentinel.resolveSibling("phase")
        val command = mutableListOf<String>()
        if (System.getProperty("os.name").lowercase().contains("linux") && System.getenv("DISPLAY").isNullOrBlank()) {
            val xvfb = Path.of("/usr/bin/xvfb-run")
            assertTrue(Files.isExecutable(xvfb),
                "Desktop Compose exit regression requires /usr/bin/xvfb-run when DISPLAY is absent; install xvfb in Fast Checks.")
            command += listOf(xvfb.toString(), "-a")
        }
        command += listOf(java, "-Djava.awt.headless=false", "-Dskiko.renderApi=SOFTWARE", "-cp", classpath,
            DesktopComposeApplicationExitChild::class.java.name, sentinel.toString(), phase.toString())
        val process = ProcessBuilder(command)
            .redirectErrorStream(true).redirectOutput(output.toFile()).start()
        try {
            val exited = process.waitFor(15, TimeUnit.SECONDS)
            if (!exited) {
                assertTrue(false, "Windowless Compose child did not exit: ${read(output)}; ${timeoutDiagnostic(process, sentinel, phase)}")
            }
            assertEquals(0, process.exitValue(), read(output))
            return read(output)
        } finally {
            // The process and all descendants are exact test-owned windowless Compose/Xvfb children.
            if (process.isAlive) {
                process.descendants().forEach { it.destroy() }
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.descendants().forEach { it.destroyForcibly() }
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
            }
        }
    }

    private fun read(path: Path): String = if (Files.exists(path)) Files.readString(path) else "<no child output>"

    private fun timeoutDiagnostic(process: Process, sentinel: Path, phase: Path): String {
        val directory = sentinel.parent.toString()
        val phaseValue = read(phase).take(256).replace(directory, "<test-dir>")
        return "childPid=${process.pid()}; finallyExists=${Files.exists(sentinel)}; phase=$phaseValue; " +
            "threadDump=${ownedChildJvm(process)?.let { childThreadDump(it, sentinel.parent) } ?: "<no exact live child JVM>"}"
    }

    private fun ownedChildJvm(process: Process): ProcessHandle? {
        val candidates = mutableListOf(process.toHandle())
        process.descendants().use { descendants -> descendants.forEach(candidates::add) }
        return candidates.singleOrNull { candidate ->
            if (!candidate.isAlive) return@singleOrNull false
            val info = candidate.info()
            val executable = info.command().orElse("").substringAfterLast('/').substringAfterLast('\\').lowercase()
            val arguments = info.arguments().orElse(emptyArray()).joinToString(" ")
            executable in setOf("java", "java.exe") && arguments.contains(DesktopComposeApplicationExitChild::class.java.name)
        }
    }

    private fun childThreadDump(child: ProcessHandle, directory: Path): String {
        if (!child.isAlive) return "<child JVM exited before dump>"
        val executable = if (System.getProperty("os.name").startsWith("Windows")) "jcmd.exe" else "jcmd"
        val jcmd = Path.of(System.getProperty("java.home"), "bin", executable)
        if (!Files.isExecutable(jcmd)) return "<jcmd unavailable>"
        val dump = Files.createTempFile(directory, "child-thread-dump", ".log")
        val directoryText = directory.toString()
        return try {
            val collector = ProcessBuilder(jcmd.toString(), child.pid().toString(), "Thread.print")
                .redirectErrorStream(true).redirectOutput(dump.toFile()).start()
            if (!collector.waitFor(2, TimeUnit.SECONDS)) {
                collector.destroyForcibly()
                collector.waitFor(2, TimeUnit.SECONDS)
                "<jcmd timed out>"
            } else {
                read(dump).take(12_000).replace(directoryText, "<test-dir>")
            }
        } catch (error: Exception) {
            "<jcmd failed: ${error.javaClass.simpleName}>"
        } finally {
            Files.deleteIfExists(dump)
        }
    }
}

object DesktopComposeApplicationExitChild {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2)
        val sentinel = Path.of(arguments[0])
        val phase = Path.of(arguments[1])
        fun mark(value: String) = Files.writeString(phase, value)
        mark("before-runner")
        runDesktopFrontendProcess(
            content = {
                mark("composed")
                mark("exit-requested")
                exitApplication()
            },
            teardown = {
                Files.writeString(sentinel, "finally")
                mark("finally")
            },
        )
        mark("returned")
    }
}
