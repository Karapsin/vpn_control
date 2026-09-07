package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.io.ByteArrayOutputStream
import kotlin.test.*

class DesktopRawExportTest {
    @Test fun desktopAndAndroidRawTextUseExactBoundedUtf8WithoutSuccessSuffix() {
        val content = "a".repeat(8191) + "東京😀".repeat(2000)
        for (android in listOf(false, true)) {
            val output = ByteArrayOutputStream()
            val lines = mutableListOf<String>()
            val errors = mutableListOf<String>()
            val args = (if (android) listOf("--android") else emptyList()) +
                listOf("routing", "export", "--output", "-")
            assertEquals(0, DesktopCli.handleArgs(args.toTypedArray(), printLine = lines::add,
                printProgress = errors::add, requestCommand = { response(assertIs<DesktopCliCommand.ControlSubmit>(it).request, content) },
                androidRequest = { request, _, _ -> response(request, content) },
                writeBinaryOutput = { path, bytes ->
                    assertEquals("-", path)
                    assertTrue(bytes.size in 1..8192)
                    output.write(bytes)
                    Result.success(Unit)
                }))
            assertContentEquals(content.toByteArray(Charsets.UTF_8), output.toByteArray())
            assertTrue(lines.isEmpty()); assertTrue(errors.isEmpty())
        }
    }

    @Test fun partialSinkFailureStopsBothPlatformsAndWritesOnlyStderr() {
        for (android in listOf(false, true)) {
            var calls = 0
            val lines = mutableListOf<String>()
            val errors = mutableListOf<String>()
            val content = "x".repeat(50_000)
            val args = (if (android) listOf("--android") else emptyList()) +
                listOf("routing", "export", "--output", "-")
            assertEquals(1, DesktopCli.handleArgs(args.toTypedArray(), printLine = lines::add,
                printProgress = errors::add, requestCommand = { response(assertIs<DesktopCliCommand.ControlSubmit>(it).request, content) },
                androidRequest = { request, _, _ -> response(request, content) },
                writeBinaryOutput = { _, _ ->
                    if (++calls == 2) Result.failure(java.io.IOException("PRIVATE_DESTINATION"))
                    else Result.success(Unit)
                }))
            assertEquals(2, calls)
            assertTrue(lines.isEmpty())
            assertEquals(listOf("PERSISTENCE_FAILED"), errors)
        }
    }

    @Test fun guardedDesktopRawExportUnwrapsOnlyContent() {
        val bytes = ByteArrayOutputStream()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--controller-id", "owner", "routing", "export", "--output", "-"),
            printLine = { error("No envelope") }, requestCommand = { command ->
                response((command as DesktopCliCommand.ControlSubmit).request, "東京")
            }, writeBinaryOutput = { _, chunk -> bytes.write(chunk); Result.success(Unit) }))
        assertEquals("東京", bytes.toString("UTF-8"))
    }

    private fun response(request: ControlRequest, content: String) = DesktopCliResponse.success(
        ControlDocumentCodec.encodeResult(ControlResult("owner", request.requestId, ControlCode.OK, 1,
            data = mapOf("content" to ControlValue.Text(content)))))
}
