package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlin.test.*

class DesktopAndroidCliTest {
    @Test fun diagnosticsExportUsesAndroidReportAndNeverStartsDesktopOwner() {
        val lines = mutableListOf<String>()
        var written = ""
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "--json", "diagnostics", "export", "--output", "report.txt"),
            printLine = lines::add, requestCommand = { error("Desktop owner must not be contacted") },
            startHeadlessController = { error("Desktop owner must not start") }, androidRequest = { request, _, _ ->
                assertEquals(ControlOperationId.DIAGNOSTICS_EXPORT, request.command.operation)
                assertTrue(request.command.arguments.isEmpty())
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android", request.requestId,
                    ControlCode.OK, 3, data = mapOf("content" to ControlValue.Text("SANITIZED_ANDROID_REPORT")))))
            }, writeOutput = { path, content -> assertEquals("report.txt", path); written = content; Result.success(Unit) }))
        assertEquals("SANITIZED_ANDROID_REPORT", written)
        assertFalse(lines.single().contains("SANITIZED_ANDROID_REPORT"))
    }
    @Test fun androidFileExportNeverOverwritesExistingLocalDestination() {
        val directory = Files.createTempDirectory("android-export-東京")
        val destination = directory.resolve("saved.json")
        try {
            Files.writeString(destination, "KEEP_EXISTING")
            val lines = mutableListOf<String>()
            assertEquals(1, DesktopCli.handleArgs(arrayOf("--android", "--json", "routing", "export",
                "--output", destination.toString()), printLine = lines::add, androidRequest = { request, _, _ ->
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android", request.requestId,
                    ControlCode.OK, 2, data = mapOf("content" to ControlValue.Text("NEW_CONTENT")))))
            }))
            assertEquals("KEEP_EXISTING", Files.readString(destination))
            assertEquals(ControlCode.PERSISTENCE_FAILED, ControlProtocolCodec.decodeResult(lines.single()).code)
        } finally { Files.deleteIfExists(destination); Files.delete(directory) }
    }

    @Test fun androidQrStdoutIsOnlyPngBytesAndFormatNeverReachesDevice() {
        val lines = mutableListOf<String>()
        var output: ByteArray? = null
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "locations", "export", "--format", "qr-png", "--output", "-"),
            printLine = lines::add, androidRequest = { request, _, _ ->
                assertTrue(request.command.arguments.isEmpty())
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android", request.requestId,
                    ControlCode.OK, 2, data = mapOf("content" to ControlValue.Text("socks://127.0.0.1:1080")))))
            }, writeBinaryOutput = { _, bytes -> output = bytes; Result.success(Unit) }))
        assertTrue(lines.isEmpty())
        assertContentEquals(byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
            requireNotNull(output).take(8).toByteArray())
    }
    @Test fun androidExportWritesClientFileAndReturnsEnvelopeOnlyAfterSuccessfulWrite() {
        val lines = mutableListOf<String>()
        var writes = 0
        val args = arrayOf("--android", "--json", "routing", "export", "--output", "local 東京.json")
        val request: (ControlRequest, String?, Long) -> DesktopCliResponse = { request, _, _ ->
            assertTrue(request.command.arguments.isEmpty())
            DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android", request.requestId,
                ControlCode.OK, 8, data = mapOf("content" to ControlValue.Text("PRIVATE_CONFIG")))))
        }
        assertEquals(0, DesktopCli.handleArgs(args, printLine = lines::add, androidRequest = request,
            writeOutput = { path, content ->
                assertEquals("local 東京.json", path); assertEquals("PRIVATE_CONFIG", content)
                writes++; Result.success(Unit)
            }))
        assertEquals(1, writes)
        assertFalse(lines.single().contains("PRIVATE_CONFIG"))
        assertEquals(8, ControlProtocolCodec.decodeResult(lines.single()).configurationRevision)
        lines.clear()
        assertEquals(1, DesktopCli.handleArgs(args, printLine = lines::add, androidRequest = request,
            writeOutput = { _, _ -> Result.failure(java.io.IOException("private destination")) }))
        assertEquals(ControlCode.PERSISTENCE_FAILED, ControlProtocolCodec.decodeResult(lines.single()).code)
        assertFalse(lines.single().contains("private destination"))
    }

    @Test fun androidRawExportHasNoEnvelopeOrSuccessSuffixAndReportsWriteFailureOnStderr() {
        val lines = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val args = arrayOf("--android", "locations", "export", "--output", "-")
        val request: (ControlRequest, String?, Long) -> DesktopCliResponse = { request, _, _ ->
            assertTrue(request.command.arguments.isEmpty())
            DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android", request.requestId,
                ControlCode.OK, 4, data = mapOf("content" to ControlValue.Text("東京\n")))))
        }
        assertEquals(0, DesktopCli.handleArgs(args, printLine = lines::add, printProgress = errors::add,
            androidRequest = request, writeBinaryOutput = { path, bytes ->
                assertEquals("-", path); assertContentEquals("東京\n".toByteArray(), bytes); Result.success(Unit)
            }))
        assertTrue(lines.isEmpty()); assertTrue(errors.isEmpty())
        assertEquals(1, DesktopCli.handleArgs(args, printLine = lines::add, printProgress = errors::add,
            androidRequest = request, writeBinaryOutput = { _, _ -> Result.failure(java.io.IOException("private")) }))
        assertTrue(lines.isEmpty()); assertEquals(listOf("PERSISTENCE_FAILED"), errors)
    }
    @Test fun androidGuardTransfersExplicitOwnerAndRevisionWithoutRebinding() {
        val lines = mutableListOf<String>()
        assertEquals(1, DesktopCli.handleArgs(arrayOf("--android", "--json", "--controller-id", "observed-owner",
            "--if-revision", "7", "settings", "set", "language", "en"), printLine = lines::add,
            androidRequest = { request, _, _ ->
                assertEquals("observed-owner", request.controllerId)
                assertEquals(7L, request.ifRevision)
                DesktopCliResponse.failure(ControlProtocolCodec.encodeResult(ControlResult("replacement-owner",
                    request.requestId, ControlCode.CONFLICT, 7)))
            }))
        assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(lines.single()).code)
    }

    @Test fun androidCapabilitiesUseSelectedDeviceNotDesktopStaticInventory() {
        val lines = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "--serial", "device-two", "--json", "capabilities"),
            printLine = lines::add,
            requestCommand = { error("Do not contact desktop owner") },
            startHeadlessController = { error("Do not start desktop owner") },
            androidRequest = { request, serial, timeout ->
                assertEquals("device-two", serial)
                assertEquals(600L, timeout)
                assertEquals(ControlOperationId.CAPABILITIES, request.command.operation)
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("android-owner", request.requestId,
                    ControlCode.OK, 0, data = mapOf("scope" to ControlValue.Text("android-read-only-provider")))))
            }))
        assertEquals("android-owner", ControlProtocolCodec.decodeResult(lines.single()).controllerId)
    }

    @Test fun helpInvalidArgumentsAndUnsupportedDesktopCommandsDoNotInvokeAdb() {
        for ((args, expected) in listOf(
            arrayOf("--android", "--help") to 0,
            arrayOf("--android", "--version") to 0,
            arrayOf("--android", "capabilities", "--typo") to 1,
            arrayOf("--android", "serve") to 1,
            arrayOf("--android", "logs", "--follow") to 1,
            arrayOf("--serial", "device", "settings", "show") to 1,
            arrayOf("--android", "--state-dir", "missing", "settings", "show") to 1,
        )) assertEquals(expected, DesktopCli.handleArgs(args, printLine = {},
            requestCommand = { error("No desktop requests") }, androidRequest = { _, _, _ -> error("No adb requests") }))
    }

    @Test fun fileContentIsNotReplacedByDeviceSidePathsAndUnsupportedIsPreserved() {
        val file = Files.createTempFile("android-input-東京", ".json")
        try {
            Files.writeString(file, "{\"dns.endpoint\":\"https://private.example/dns-query\"}")
            val lines = mutableListOf<String>()
            assertEquals(1, DesktopCli.handleArgs(arrayOf("settings", "apply", "--input", file.toString(), "--android", "--json"),
                printLine = lines::add, androidRequest = { request, _, _ ->
                    assertEquals(Files.readString(file), (request.command.arguments["input"] as ControlValue.Text).value)
                    DesktopCliResponse(false, ControlProtocolCodec.encodeResult(ControlResult("android-owner", request.requestId,
                        ControlCode.UNSUPPORTED, 0)), 1)
                }))
            assertEquals(ControlCode.UNSUPPORTED, ControlProtocolCodec.decodeResult(lines.single()).code)
        } finally { Files.delete(file) }
    }
}
