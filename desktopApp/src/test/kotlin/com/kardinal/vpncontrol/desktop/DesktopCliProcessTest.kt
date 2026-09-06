package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopCliProcessTest {
    @Test
    fun realHeadlessCliKeepsTwoUnicodeWorkspacesIsolated() {
        val root = Files.createTempDirectory("vpn-control-process-test")
        val first = root.resolve("東京 first")
        val second = root.resolve("second space")
        val javaName = if (System.getProperty("os.name").lowercase().contains("windows")) "java.exe" else "java"
        val java = Path.of(System.getProperty("java.home"), "bin", javaName).toString()
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        var sequence = 0
        val processes = mutableListOf<Process>()
        fun start(vararg args: String): Pair<Process, Path> {
            val output = root.resolve("process-${sequence++}.log")
            val builder = ProcessBuilder(listOf(java, "-Djava.awt.headless=true", "-Dfile.encoding=windows-1251",
                "-Dsun.stdout.encoding=windows-1251", "-cp", classpath,
                DesktopJvmCliTestBootstrap::class.java.name) + DesktopJvmCliTestBootstrap.encode(args.toList()))
            builder.environment().remove("DISPLAY")
            builder.environment().remove("WAYLAND_DISPLAY")
            builder.redirectErrorStream(true).redirectOutput(output.toFile())
            return builder.start().also { processes += it } to output
        }
        fun invoke(workspace: Path, vararg args: String): Pair<Int, String> {
            val (process, output) = start("--state-dir", workspace.toString(), *args)
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "CLI process timed out")
            return process.exitValue() to Files.readString(output)
        }
        try {
            assertEquals(0, invoke(first, "--help").first)
            assertFalse(Files.exists(first))
            val capabilities = invoke(first, "--json", "capabilities")
            assertEquals(0, capabilities.first, capabilities.second)
            assertEquals(null, ControlProtocolCodec.decodeResult(capabilities.second.trim()).controllerId)
            assertFalse(Files.exists(first))
            val invalidJson = invoke(first, "--json", "settings", "show", "--typo")
            assertEquals(1, invalidJson.first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT,
                ControlProtocolCodec.decodeResult(invalidJson.second.trim()).code)
            assertFalse(Files.exists(first))
            val notDirectory = root.resolve("private workspace file")
            Files.writeString(notDirectory, "test-owned sentinel")
            val invalidPath = invoke(notDirectory, "--json", "settings", "show")
            assertEquals(1, invalidPath.first)
            val pathError = ControlProtocolCodec.decodeResult(invalidPath.second.trim())
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT, pathError.code)
            assertEquals(null, pathError.controllerId)
            assertFalse(invalidPath.second.contains("private workspace file"))
            assertEquals("test-owned sentinel", Files.readString(notDirectory))
            assertEquals(2, invoke(first, "status").first)
            assertFalse(Files.exists(first))
            val noOwnerStatus = invoke(first, "--json", "status")
            assertEquals(2, noOwnerStatus.first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE,
                ControlProtocolCodec.decodeResult(noOwnerStatus.second.trim()).code)
            assertFalse(Files.exists(first))
            assertEquals(1, invoke(first, "settings", "show", "--typo").first)
            assertFalse(Files.exists(first))
            for (workspace in listOf(first, second)) {
                val (owner, log) = start("--state-dir", workspace.toString(), "serve")
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
                while (!Files.exists(workspace.resolve("activation.port")) && owner.isAlive && System.nanoTime() < deadline) {
                    Thread.sleep(20)
                }
                assertTrue(owner.isAlive && Files.exists(workspace.resolve("activation.port")), Files.readString(log))
                assertEquals(0, invoke(workspace, "status").first)
            }
            val saved = invoke(first, "settings", "set", "validation.batch-size", "7")
            assertEquals(0, saved.first, saved.second)
            val firstSettings = invoke(first, "settings", "show", "validation.batch-size")
            val secondSettings = invoke(second, "settings", "show", "validation.batch-size")
            assertEquals(0, firstSettings.first, firstSettings.second)
            assertEquals(0, secondSettings.first, secondSettings.second)
            assertTrue(firstSettings.second.contains("7"))
            assertTrue(firstSettings.second != secondSettings.second)
            // No manifest was checked: this operation fails locally without network or installation.
            val submitted = invoke(first, "--json", "--async", "updates", "download")
            val result = ControlProtocolCodec.decodeResult(submitted.second.trim())
            assertEquals(result.exitCode, submitted.first)
            assertEquals(1L, result.configurationRevision)
            assertFalse(result.restartRequired)
            val operationId = assertNotNull(result.operationId)
            val completed = invoke(first, "operations", "wait", operationId)
            assertEquals(1, completed.first, completed.second)
            val terminal = Json.parseToJsonElement(completed.second).jsonObject
            assertEquals("true", terminal.getValue("final").jsonPrimitive.content)
            assertEquals("1", terminal.getValue("configurationRevision").jsonPrimitive.content)
            assertEquals(result.controllerId, terminal.getValue("controllerId").jsonPrimitive.content)
            val changedAgain = invoke(first, "settings", "set", "validation.batch-size", "8")
            assertEquals(0, changedAgain.first, changedAgain.second)
            val retained = invoke(first, "operations", "status", operationId)
            assertEquals(0, retained.first, retained.second)
            assertEquals(terminal, Json.parseToJsonElement(retained.second).jsonObject)
            val jsonSettings = invoke(first, "--json", "settings", "show", "validation.batch-size")
            assertEquals(0, jsonSettings.first, jsonSettings.second)
            val inspected = ControlProtocolCodec.decodeResult(jsonSettings.second.trim())
            assertEquals(2L, inspected.configurationRevision)
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.IntegerValue(8), inspected.data["validation.batch-size"])
            val jsonSaved = invoke(first, "settings", "set", "validation.batch-size", "9", "--json")
            assertEquals(0, jsonSaved.first, jsonSaved.second)
            assertEquals(3L, ControlProtocolCodec.decodeResult(jsonSaved.second.trim()).configurationRevision)
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.IntegerValue(9),
                ControlProtocolCodec.decodeResult(jsonSaved.second.trim()).data["validation.batch-size"])
            val input = root.resolve("settings input.json")
            Files.writeString(input, "{\"validation.batch-size\":10}")
            val jsonApplied = invoke(first, "--json", "settings", "apply", "--input", input.toString())
            assertEquals(0, jsonApplied.first, jsonApplied.second)
            assertEquals(4L, ControlProtocolCodec.decodeResult(jsonApplied.second.trim()).configurationRevision)
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.IntegerValue(10),
                ControlProtocolCodec.decodeResult(jsonApplied.second.trim()).data["validation.batch-size"])
            val jsonMissing = invoke(first, "--json", "settings", "show", "missing")
            assertEquals(1, jsonMissing.first)
            assertEquals(com.kardinal.vpncontrol.model.ControlCode.NOT_FOUND,
                ControlProtocolCodec.decodeResult(jsonMissing.second.trim()).code)
            for (arguments in listOf(arrayOf("stats"), arrayOf("logs", "--limit", "0"),
                    arrayOf("source", "show"), arrayOf("settings", "languages"), arrayOf("locations", "list"),
                    arrayOf("subscriptions", "list"), arrayOf("routing", "show"), arrayOf("ssh", "key", "status"),
                    arrayOf("updates", "status"))) {
                val read = invoke(first, "--json", *arguments)
                assertEquals(0, read.first, read.second)
                val envelope = ControlProtocolCodec.decodeResult(read.second.trim())
                assertEquals(inspected.controllerId, envelope.controllerId)
                assertEquals(4L, envelope.configurationRevision)
                assertTrue(envelope.final)
                assertTrue(envelope.data.isNotEmpty())
                if (arguments.contentEquals(arrayOf("settings", "languages"))) {
                    val languages = envelope.data.getValue("languages") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue
                    assertTrue(languages.values.any { value ->
                        val entry = (value as com.kardinal.vpncontrol.model.ControlValue.ObjectValue).values
                        entry["name"] == com.kardinal.vpncontrol.model.ControlValue.Text(
                            com.kardinal.vpncontrol.model.AppLanguage.entries.first { it.code == "ja" }.nativeName)
                    })
                }
            }
            assertTrue(Files.exists(first.resolve("workspace.json")))
            assertTrue(Files.exists(second.resolve("workspace.json")))
            val locationInput = root.resolve("location input 東京.txt")
            Files.writeString(locationInput, "socks://127.0.0.1:1080#Process fixture")
            for (arguments in listOf(arrayOf("source", "set", "current-locations"),
                    arrayOf("locations", "add", "--input", locationInput.toString()),
                    arrayOf("select", "Process fixture"), arrayOf("routing", "set", "ignore-rules", "true"),
                    arrayOf("locations", "delete", "Process fixture"))) {
                val write = invoke(first, "--json", *arguments)
                assertEquals(0, write.first, write.second)
                val envelope = ControlProtocolCodec.decodeResult(write.second.trim())
                assertEquals(inspected.controllerId, envelope.controllerId)
                assertTrue(envelope.final)
                assertNotNull(envelope.operationId)
            }
        } finally {
            // Only these test-owned, never-connected processes are stopped.
            processes.filter { it.isAlive }.forEach {
                it.destroy()
                if (!it.waitFor(5, TimeUnit.SECONDS)) { it.destroyForcibly(); it.waitFor(5, TimeUnit.SECONDS) }
            }
            root.toFile().deleteRecursively()
        }
    }
}
