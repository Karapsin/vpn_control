package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DesktopQrCliTest {
    @Test fun imageInputIsDecodedLocallyAndKeepsItsOriginalCommandMeaning() {
        val directory = Files.createTempDirectory("cli-qr-東京")
        try {
            val input = directory.resolve("QR input.png")
            val content = "socks://127.0.0.1:1080#東京"
            Files.write(input, DesktopQrImage.encode(content).getOrThrow())
            for ((args, expected) in listOf(
                listOf("locations", "add") to DesktopCliCommand.LocationSave(content),
                listOf("locations", "import") to DesktopCliCommand.LocationsImport(content),
                listOf("routing", "import") to DesktopCliCommand.RoutingImport(content),
                listOf("subscriptions", "add") to DesktopCliCommand.SubscriptionSave(content, null, null),
            )) {
                assertEquals(0, DesktopCli.handleArgs((args + listOf("--qr-image", input.toString())).toTypedArray(),
                    printLine = {}, requestCommand = { assertEquals(expected, it); DesktopCliResponse.success("OK") }))
                DesktopCli.handleArgs((listOf("--json") + args + listOf("--qr-image", input.toString())).toTypedArray(),
                    printLine = {}, requestCommand = {
                        val typed = assertIs<DesktopCliCommand.ControlSubmit>(it).request.command
                        assertEquals(ControlValue.Text(content), typed.arguments["input"])
                        assertFalse("qr-image" in typed.arguments)
                        DesktopCliResponse.failure("UNAVAILABLE", 2)
                    })
            }
            assertEquals(1, DesktopCli.handleArgs(arrayOf("locations", "add", "--qr-image", input.toString(), "--input", "-"),
                printLine = {}, requestCommand = { error("Invalid grammar must not contact owner") },
                readQrImage = { error("Invalid grammar must not read image") }))
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun pngStdoutIsBinaryAndDoesNotGainATextAcknowledgement() {
        val lines = mutableListOf<String>()
        val payload = "{\"locations\":[]}"
        var written = false
        assertEquals(0, DesktopCli.handleArgs(arrayOf("locations", "export", "--format", "qr-png", "--output", "-"),
            printLine = lines::add, requestCommand = { DesktopCliResponse.success(payload) },
            writeBinaryOutput = { path, bytes ->
                assertEquals("-", path)
                assertEquals(payload, DesktopQrImage.decode(bytes).getOrThrow())
                written = true
                Result.success(Unit)
            }))
        assertTrue(written)
        assertTrue(lines.isEmpty())
        assertEquals(1, DesktopCli.handleArgs(arrayOf("locations", "export", "--format", "qr-png", "--output", "-", "--json"),
            printLine = {}, requestCommand = { error("JSON cannot be mixed with PNG stdout") }))
    }

    @Test fun sizeAndExistingDestinationFailuresDoNotOverwriteOutput() {
        val directory = Files.createTempDirectory("cli-qr-output")
        try {
            val output = directory.resolve("東京 export.png")
            val args = arrayOf("routing", "export", "--format", "qr-png", "--output", output.toString())
            assertEquals(1, DesktopCli.handleArgs(args, printLine = {},
                requestCommand = { DesktopCliResponse.success("a".repeat(1601)) }))
            assertFalse(Files.exists(output))
            Files.writeString(output, "sentinel")
            assertEquals(1, DesktopCli.handleArgs(args, printLine = {},
                requestCommand = { DesktopCliResponse.success("payload") }))
            assertEquals("sentinel", Files.readString(output))
        } finally { directory.toFile().deleteRecursively() }
    }
}
