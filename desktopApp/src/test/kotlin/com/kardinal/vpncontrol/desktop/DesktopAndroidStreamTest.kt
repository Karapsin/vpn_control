package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopAndroidStreamTest {
    private fun response(request: ControlRequest, data: Map<String, ControlValue> = emptyMap(),
                         owner: String = "android-owner", code: ControlCode = ControlCode.OK): DesktopCliResponse {
        val result = ControlResult(owner, request.requestId, code, 8, data = data)
        return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
    }

    @Test fun androidWatchUsesSelectedDeviceAndPinsAuthenticatedOwner() {
        for (operation in listOf("status", "stats")) {
            var reads = 0
            val output = mutableListOf<String>()
            assertEquals(130, DesktopCli.handleArgs(arrayOf("--android", "--serial", "task-device", "--json",
                operation, "--watch", "--timeout-seconds", "2"), printLine = output::add,
                requestCommand = { error("Desktop request") }, startHeadlessController = { error("Desktop startup") },
                androidRequest = { request, serial, timeout ->
                    assertEquals("task-device", serial)
                    assertEquals(2, timeout)
                    assertEquals(if (reads++ == 0) null else "android-owner", request.controllerId)
                    assertEquals(operation, request.command.operation.wireName)
                    response(request, mapOf("running" to ControlValue.Null))
                }, streamPause = {}, streamActive = { reads < 2 }))
            val results = output.map(ControlDocumentCodec::decodeResult)
            assertEquals(listOf(ControlCode.OK, ControlCode.OK, ControlCode.CANCELLED), results.map { it.code })
            assertTrue(results.take(2).all { !it.final })
        }
    }

    @Test fun androidHumanWatchKeepsOwnerMetadataWarningsAndDataOnStderr() {
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        var reads = 0
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--android", "status", "--watch"),
            printLine = stdout::add, printProgress = stderr::add, androidRequest = { request, _, _ ->
                assertEquals(if (reads++ == 0) null else "android-owner", request.controllerId)
                val result = ControlResult("android-owner", request.requestId, ControlCode.OK, 8,
                    final = true, data = mapOf("running" to ControlValue.Null), warnings = listOf("STALE_DATA"))
                DesktopCliResponse.success(ControlDocumentCodec.encodeResult(result))
            }, streamPause = {}, streamActive = { reads < 1 }))
        assertTrue(stdout.isEmpty(), "Human stream records belong on stderr")
        assertTrue(stderr.first().contains("Controller: android-owner"))
        assertTrue(stderr.first().contains("Request:"))
        assertTrue(stderr.first().contains("Revision: 8"))
        assertTrue(stderr.first().contains("Completion: pending"))
        assertTrue(stderr.first().contains("Warnings:\n  - STALE_DATA"))
        assertTrue(stderr.first().contains("Data:\n  running: unknown"))
    }

    @Test fun androidFollowKeepsDuplicateMessagesAndUsesTailCursorAfterLimitZero() {
        var reads = 0
        val output = mutableListOf<String>()
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--android", "--json", "logs", "--follow", "--limit", "0"),
            printLine = output::add, androidRequest = { request, _, _ ->
                val initial = reads++ == 0
                assertEquals(ControlValue.Text(if (initial) "0" else "100"), request.command.arguments["limit"])
                assertEquals(if (initial) null else ControlValue.Text("cursor-0"), request.command.arguments["after"])
                response(request, mapOf(
                    "entries" to ControlValue.ArrayValue(if (initial) emptyList() else (1..2).map { id ->
                        ControlValue.ObjectValue(mapOf("id" to ControlValue.Text("cursor-$id"),
                            "createdAtEpochMillis" to ControlValue.IntegerValue(1), "message" to ControlValue.Text("same")))
                    }), "nextCursor" to ControlValue.Text(if (initial) "cursor-0" else "cursor-2"),
                    "gap" to ControlValue.BooleanValue(!initial)))
            }, streamPause = {}, streamActive = { reads < 2 }))
        val delivered = ControlDocumentCodec.decodeResult(output[1])
        assertEquals(2, (delivered.data["entries"] as ControlValue.ArrayValue).values.size)
        assertTrue("LOG_HISTORY_GAP" in delivered.warnings)
    }

    @Test fun androidOwnerReplacementAndDeviceLossEndObservationWithoutRetry() {
        for (code in listOf(ControlCode.CONFLICT, ControlCode.UNAVAILABLE)) {
            var reads = 0
            val output = mutableListOf<String>()
            assertEquals(code.exitCode, DesktopCli.handleArgs(arrayOf("--android", "--json", "status", "--watch"),
                printLine = output::add, androidRequest = { request, _, _ ->
                    if (reads++ == 0) response(request) else {
                        assertEquals("android-owner", request.controllerId)
                        if (code == ControlCode.CONFLICT) response(request, owner = "new-owner", code = code)
                        else desktopCliJsonFailure(code, request.requestId)
                    }
                }, streamPause = {}))
            assertEquals(2, reads)
            assertEquals(code, ControlDocumentCodec.decodeResult(output.last()).code)
        }
    }

    @Test fun closedAndroidStreamOutputStopsWithoutCancellingOwnerWork() {
        var reads = 0
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--android", "--json", "stats", "--watch"),
            printLine = { throw java.io.IOException("closed") }, androidRequest = { request, _, _ ->
                reads++
                assertEquals(ControlOperationId.STATS, request.command.operation)
                response(request)
            }, streamPause = { error("No further polling") }))
        assertEquals(1, reads)
    }
}
