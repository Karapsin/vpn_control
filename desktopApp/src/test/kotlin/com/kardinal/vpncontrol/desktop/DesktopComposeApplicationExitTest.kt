package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * This is a real product-runner child JVM. It creates no Window, app workspace, owner, or runtime.
 */
class DesktopComposeApplicationExitTest {
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
        val command = mutableListOf<String>()
        if (System.getProperty("os.name").lowercase().contains("linux") && System.getenv("DISPLAY").isNullOrBlank()) {
            val xvfb = Path.of("/usr/bin/xvfb-run")
            assertTrue(Files.isExecutable(xvfb),
                "Desktop Compose exit regression requires /usr/bin/xvfb-run when DISPLAY is absent; install xvfb in Fast Checks.")
            command += listOf(xvfb.toString(), "-a")
        }
        command += listOf(java, "-Djava.awt.headless=false", "-cp", classpath,
            DesktopComposeApplicationExitChild::class.java.name, sentinel.toString())
        val process = ProcessBuilder(command)
            .redirectErrorStream(true).redirectOutput(output.toFile()).start()
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "Windowless Compose child did not exit: ${read(output)}")
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
}

object DesktopComposeApplicationExitChild {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 1)
        val sentinel = Path.of(arguments[0])
        try {
            runDesktopFrontendApplication { exitApplication() }
        } finally {
            Files.writeString(sentinel, "finally")
        }
    }
}
