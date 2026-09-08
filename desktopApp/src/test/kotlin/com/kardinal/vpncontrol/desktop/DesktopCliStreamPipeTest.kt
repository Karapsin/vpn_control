package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real output pipes: an injected throwing printer cannot reproduce an idle follow. */
class DesktopCliStreamPipeTest {
    @Test fun emptyJsonLogFollowStopsWhenItsReaderCloses() = verifyClosedReader(true)
    @Test fun emptyHumanLogFollowStopsWhenItsReaderCloses() = verifyClosedReader(false)
    @Test fun openPipesAndRegularFilesKeepFollowing() {
        for (json in listOf(false, true)) for (regularFile in listOf(false, true)) {
            verifyClosedReader(json, closeReader = false, regularFile = regularFile)
        }
    }

    private fun verifyClosedReader(json: Boolean, closeReader: Boolean = true, regularFile: Boolean = false) {
        val directory = Files.createTempDirectory("vpn-empty-follow-pipe")
        val ready = directory.resolve("ready")
        val otherOutput = directory.resolve("other-output")
        val javaName = if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java"
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        val builder = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin", javaName).toString(),
            "-Djava.awt.headless=true", "-cp", classpath, DesktopEmptyLogPipeChild::class.java.name) +
            DesktopJvmCliTestBootstrap.encode(listOf(ready.toString(), json.toString())))
        if (json) builder.redirectError(otherOutput.toFile()) else builder.redirectOutput(otherOutput.toFile())
        if (regularFile) {
            val selected = directory.resolve("selected-output").toFile()
            if (json) builder.redirectOutput(selected) else builder.redirectError(selected)
        }
        val process = builder.start()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
            while (!Files.exists(ready) && process.isAlive && System.nanoTime() < deadline) Thread.sleep(20)
            assertTrue(Files.exists(ready) && process.isAlive,
                "Child must enter idle follow before closing its reader: ${Files.readString(otherOutput)}")
            if (closeReader) {
                // No signal and no simulated IOException: close the actual selected consumer.
                (if (json) process.inputStream else process.errorStream).close()
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Idle follow kept polling after its consumer closed")
                assertEquals(130, process.exitValue())
            } else {
                assertFalse(process.waitFor(1, TimeUnit.SECONDS), "A healthy output must not terminate observation")
            }
            assertEquals("", Files.readString(otherOutput), "Closure must not produce output on the other channel")
        } finally {
            // This exact child has only an inert transport; it never starts an owner/runtime.
            if (process.isAlive) {
                process.destroy()
                if (!process.waitFor(5, TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
            }
            directory.toFile().deleteRecursively()
        }
    }
}

object DesktopEmptyLogPipeChild {
    @JvmStatic fun main(arguments: Array<String>) {
        val decoded = arguments.map { Base64.getDecoder().decode(it).toString(Charsets.UTF_8) }
        val ready = Path.of(decoded[0])
        val json = decoded[1].toBooleanStrict()
        var reads = 0
        val cli = listOf("--android", "logs", "--follow", "--limit", "0") + if (json) listOf("--json") else emptyList()
        exitProcess(requireNotNull(DesktopCli.handleArgs(cli.toTypedArray(),
            requestCommand = { error("No desktop transport") },
            startHeadlessController = { error("No owner startup") },
            androidRequest = { request, _, _ ->
                check(request.command.operation == ControlOperationId.LOGS) { "Observation must never cancel owner work" }
                val result = ControlResult("pipe-test-owner", request.requestId, ControlCode.OK, 0,
                    data = mapOf("entries" to ControlValue.ArrayValue(emptyList()),
                        "nextCursor" to ControlValue.Text("tail-0"), "gap" to ControlValue.BooleanValue(false)))
                if (++reads == 2) Files.writeString(ready, "idle")
                DesktopCliResponse(true, ControlDocumentCodec.encodeResult(result), 0)
            })))
    }
}
