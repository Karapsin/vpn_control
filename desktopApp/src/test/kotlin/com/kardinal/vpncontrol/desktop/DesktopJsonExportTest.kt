package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopJsonExportTest {
    @Test fun oversizedQrFailsWithoutWritingAndJsonCannotMixWithRawStdout() {
        val lines = mutableListOf<String>()
        assertEquals(1, DesktopCli.handleArgs(arrayOf("--json", "locations", "export", "--output", "qr.png", "--format", "qr-png"),
            printLine = lines::add, requestCommand = { command ->
                val request = assertIs<DesktopCliCommand.ControlSubmit>(command).request
                assertTrue(request.command.arguments.isEmpty())
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner", request.requestId, ControlCode.OK, 0,
                    data = mapOf("content" to ControlValue.Text("é".repeat(801))))))
            }, writeBinaryOutput = { _, _ -> error("Oversized QR must not create a file") }))
        val result = ControlProtocolCodec.decodeResult(lines.single())
        assertEquals(ControlCode.INVALID_ARGUMENT, result.code)
        assertEquals("QR_TOO_LARGE", result.message)
        assertTrue(result.data.isEmpty())
        assertEquals(1, DesktopCli.handleArgs(arrayOf("--json", "locations", "export", "--output", "-"),
            printLine = {}, requestCommand = { error("Raw stdout with JSON must fail before owner access") }))
    }

    @Test fun clientPathsStayLocalAndOutputFailureNeverReportsOwnerReadAsExportSuccess() {
        val lines = mutableListOf<String>()
        val args = arrayOf("--json", "locations", "export", "--output", "private destination.json")
        assertEquals(1, DesktopCli.handleArgs(args, printLine = lines::add,
            requestCommand = { command ->
                val request = assertIs<DesktopCliCommand.ControlSubmit>(command).request
                assertTrue(request.command.arguments.isEmpty())
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner", request.requestId,
                    ControlCode.OK, 17, restartRequired = true, data = mapOf("content" to ControlValue.Text("private content")))))
            }, writeOutput = { _, _ -> Result.failure(java.io.IOException("secret path")) }))
        val result = ControlProtocolCodec.decodeResult(lines.single())
        assertEquals(ControlCode.PERSISTENCE_FAILED, result.code)
        assertEquals(17L, result.configurationRevision)
        assertTrue(result.restartRequired)
        assertTrue(result.data.isEmpty())
        assertFalse(lines.single().contains("private"))
        assertFalse(lines.single().contains("secret"))
    }

    @Test fun authenticatedExportsWriteRealContentAndKeepExistingDestinations() {
        val root = Files.createTempDirectory("json-export-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(root), empty)
        val owner = DesktopControllerOwner(service)
        val endpoint = root.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId))
        try {
            runBlocking { service.executeCliCommand(DesktopCliCommand.SourceSet(null)) }
            runBlocking { service.saveLocation("socks://127.0.0.1:1080#Office").getOrThrow() }
            for ((operation, format) in listOf("locations" to "json", "locations" to "qr-png", "routing" to "json",
                    "routing" to "qr-png", "diagnostics" to "json")) {
                val output = root.resolve("$operation $format export")
                val args = listOf("--json", operation, "export", "--output", output.toString()) +
                    if (operation == "diagnostics") emptyList() else listOf("--format", format)
                fun invoke(): ControlResult {
                    val lines = mutableListOf<String>()
                    val exit = DesktopCli.handleArgs(args.toTypedArray(), printLine = lines::add,
                        requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) })
                    val result = ControlProtocolCodec.decodeResult(lines.single())
                    assertEquals(exit, result.exitCode)
                    return result
                }
                val result = invoke()
                assertEquals(ControlCode.OK, result.code, "$operation $format")
                assertEquals(owner.controllerId, result.controllerId)
                assertFalse("content" in result.data)
                val bytes = Files.readAllBytes(output)
                assertTrue(bytes.isNotEmpty())
                if (format == "qr-png") assertTrue(DesktopQrImage.decode(bytes).isSuccess)
                if (operation == "diagnostics") {
                    assertEquals(ControlValue.Text("text"), result.data["format"])
                    assertTrue("METADATA_OBSERVED_AFTER_REPORT" in result.warnings)
                    assertFalse(bytes.toString(Charsets.UTF_8).contains("socks://127.0.0.1"))
                }
                assertEquals(ControlCode.PERSISTENCE_FAILED, invoke().code)
                assertContentEquals(bytes, Files.readAllBytes(output))
            }
            assertFalse(service.state.isVpnRunning)
        } finally { server.close(); owner.close(); root.toFile().deleteRecursively() }
    }
}
