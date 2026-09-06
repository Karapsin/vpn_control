package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopQrCliProcessTest {
    @Test fun realCliPngStdoutHasNoTextOrNewlineAndCanBeImportedAgain() {
        val directory = Files.createTempDirectory("qr-cli-process")
        val workspace = directory.resolve("東京 workspace")
        val javaName = if (System.getProperty("os.name").lowercase().contains("windows")) "java.exe" else "java"
        val command = listOf(Path.of(System.getProperty("java.home"), "bin", javaName).toString(),
            "-Djava.awt.headless=true", "-cp", requireNotNull(System.getProperty("vpnControl.test.mainClasspath")),
            "com.kardinal.vpncontrol.desktop.MainKt", "--state-dir", workspace.toString())
        var sequence = 0
        val processes = mutableListOf<Process>()
        fun start(vararg args: String): Triple<Process, Path, Path> {
            val stdout = directory.resolve("stdout-${sequence}")
            val stderr = directory.resolve("stderr-${sequence++}")
            val builder = ProcessBuilder(command + args)
            builder.environment().remove("DISPLAY")
            builder.environment().remove("WAYLAND_DISPLAY")
            val process = builder.redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start()
            processes += process
            return Triple(process, stdout, stderr)
        }
        fun invoke(vararg args: String): ByteArray {
            val (process, stdout, stderr) = start(*args)
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "CLI timed out")
            assertEquals(0, process.exitValue(), Files.readString(stderr))
            assertEquals("", Files.readString(stderr))
            return Files.readAllBytes(stdout)
        }
        try {
            val (owner, _, _) = start("serve")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
            while (!Files.exists(workspace.resolve("activation.port")) && owner.isAlive && System.nanoTime() < deadline) {
                Thread.sleep(20)
            }
            assertTrue(owner.isAlive && Files.exists(workspace.resolve("activation.port")))
            invoke("source", "set", "current-locations")
            val input = directory.resolve("東京 input.png")
            Files.write(input, DesktopQrImage.encode("socks://127.0.0.1:1080#Office").getOrThrow())
            invoke("locations", "add", "--qr-image", input.toString())
            val png = invoke("locations", "export", "--format", "qr-png", "--output", "-")
            assertEquals(listOf(137, 80, 78, 71, 13, 10, 26, 10), png.take(8).map { it.toInt() and 255 })
            // PNG IEND ends in this exact CRC: no printLine acknowledgement or trailing newline.
            assertEquals(listOf(174, 66, 96, 130), png.takeLast(4).map { it.toInt() and 255 })
            assertNotNull(DesktopQrImage.decode(png).getOrNull())
            Files.write(input, png)
            invoke("locations", "delete", "Office")
            invoke("locations", "import", "--qr-image", input.toString())
            assertTrue(invoke("locations", "list").toString(Charsets.UTF_8).contains("Office"))
            for (operation in listOf("locations", "routing", "diagnostics")) {
                val output = directory.resolve("$operation 東京.json")
                val response = invoke("--json", operation, "export", "--output", output.toString()).toString(Charsets.UTF_8)
                val result = com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response)
                assertEquals(com.kardinal.vpncontrol.model.ControlCode.OK, result.code)
                assertTrue(Files.size(output) > 0)
                assertTrue("content" !in result.data)
            }
            val qrOutput = directory.resolve("JSON QR 東京.png")
            invoke("--json", "locations", "export", "--output", qrOutput.toString(), "--format", "qr-png")
            assertTrue(DesktopQrImage.read(qrOutput.toString()).isSuccess)
            for (operation in listOf("status", "stats")) {
                val (watch, stdout, stderr) = start("--json", operation, "--watch")
                val watchDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (watch.isAlive && Files.readString(stdout).count { it == '\n' } < 2 && System.nanoTime() < watchDeadline) {
                    Thread.sleep(20)
                }
                assertTrue(watch.isAlive)
                val snapshots = Files.readString(stdout).split('\n').dropLast(1).map {
                    com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(it)
                }
                assertTrue(snapshots.size >= 2)
                assertTrue(snapshots.all { it.ok && !it.final })
                assertEquals("", Files.readString(stderr))
                watch.destroy() // Only this test-owned watcher; owner remains alive and disconnected.
                assertTrue(watch.waitFor(5, TimeUnit.SECONDS))
                assertTrue(owner.isAlive)
                invoke("--json", "status")
            }
        } finally {
            // Only these never-connected, test-owned processes are stopped.
            for (process in processes.filter { it.isAlive }) {
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
