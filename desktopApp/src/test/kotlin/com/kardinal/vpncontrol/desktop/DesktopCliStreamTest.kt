package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopCliStreamTest {
    @Test fun capabilitiesAdvertiseOnlyImplementedDesktopStreams() {
        val capabilities = DesktopControlSupport.describe(ControlPlatform.LINUX)
        val streams = (capabilities["streamingOperations"] as ControlValue.ArrayValue).values
        assertEquals(listOf("status", "stats", "logs"), streams.map { (it as ControlValue.Text).value })
    }

    private fun response(command: DesktopCliCommand, data: Map<String, ControlValue> = emptyMap(),
                         owner: String = "owner", code: ControlCode = ControlCode.OK): DesktopCliResponse {
        val request = assertIs<DesktopCliCommand.ControlSubmit>(command).request
        val result = ControlResult(owner, request.requestId, code, 7, data = data)
        return DesktopCliResponse(result.ok, ControlProtocolCodec.encodeResult(result), result.exitCode)
    }

    @Test fun jsonWatchPinsEpochAndEmitsOneEnvelopePerLineUntilCancelled() {
        val lines = mutableListOf<String>()
        var reads = 0
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--json", "status", "--watch", "--timeout-seconds", "2"),
            printLine = lines::add, startHeadlessController = { error("Never start an owner") },
            requestCommand = { command ->
                val submit = assertIs<DesktopCliCommand.ControlSubmit>(command)
                assertEquals(2L, submit.clientTimeoutSeconds)
                assertEquals(if (reads == 0) null else "owner", submit.request.controllerId)
                reads++
                response(command, mapOf("runtimeRunning" to ControlValue.BooleanValue(false)))
            }, streamPause = {}, streamActive = { reads < 2 }))
        val results = lines.map(ControlProtocolCodec::decodeResult)
        assertEquals(3, results.size)
        assertTrue(results.take(2).all { !it.final && it.code == ControlCode.OK })
        assertEquals(ControlCode.CANCELLED, results.last().code)
        assertTrue(results.last().final)
    }

    @Test fun missingOwnerAndReplacementOwnerTerminateWithoutStartingOrRebinding() {
        assertEquals(2, DesktopCli.handleArgs(arrayOf("status", "--watch", "--json"), printLine = {},
            requestCommand = { DesktopCliResponse.notRunning() }, startHeadlessController = { error("No startup") }))
        var reads = 0
        val lines = mutableListOf<String>()
        assertEquals(1, DesktopCli.handleArgs(arrayOf("stats", "--watch", "--json"), printLine = lines::add,
            requestCommand = {
                reads++
                if (reads == 1) response(it) else {
                    assertEquals("owner", assertIs<DesktopCliCommand.ControlSubmit>(it).request.controllerId)
                    response(it, owner = "replacement", code = ControlCode.CONFLICT)
                }
            }, streamPause = {}))
        assertEquals(2, reads)
        assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(lines.last()).code)
    }

    @Test fun humanWatchUsesProgressStreamAndDoesNotFabricateUnknownTelemetry() {
        val progress = mutableListOf<String>()
        var read = false
        assertEquals(130, DesktopCli.handleArgs(arrayOf("stats", "--watch"), printLine = { error("Human progress belongs on stderr") },
            printProgress = progress::add, requestCommand = {
                read = true
                response(it, mapOf("elapsedMillis" to ControlValue.Null))
            }, streamPause = {}, streamActive = { !read }))
        assertTrue(progress.first().contains("null"))
        assertEquals("CANCELLED", progress.last())
    }

    @Test fun logFollowUsesOpaqueCursorsNotTimestampsAndReportsHistoryGaps() {
        val lines = mutableListOf<String>()
        var reads = 0
        fun data(ids: List<String>, cursor: String, gap: Boolean = false) = mapOf(
            "entries" to ControlValue.ArrayValue(ids.map { id -> ControlValue.ObjectValue(mapOf(
                "id" to ControlValue.Text(id), "createdAtEpochMillis" to ControlValue.IntegerValue(1),
                "message" to ControlValue.Text("identical message"))) }),
            "nextCursor" to ControlValue.Text(cursor), "gap" to ControlValue.BooleanValue(gap))
        assertEquals(130, DesktopCli.handleArgs(arrayOf("--json", "logs", "--follow", "--limit", "0"), printLine = lines::add,
            requestCommand = {
                val arguments = assertIs<DesktopCliCommand.ControlSubmit>(it).request.command.arguments
                response(it, when (reads++) {
                    0 -> { assertEquals(ControlValue.Text("0"), arguments["limit"]); data(emptyList(), "cursor-0") }
                    1 -> {
                        assertEquals(ControlValue.Text("100"), arguments["limit"])
                        assertEquals(ControlValue.Text("cursor-0"), arguments["after"])
                        data(listOf("cursor-1", "cursor-2"), "cursor-2")
                    }
                    else -> {
                        assertEquals(ControlValue.Text("cursor-2"), arguments["after"])
                        data(listOf("cursor-9"), "cursor-9", gap = true)
                    }
                })
            }, streamPause = {}, streamActive = { reads < 3 }))
        val results = lines.map(ControlProtocolCodec::decodeResult)
        assertTrue("LOG_HISTORY_GAP" in results[2].warnings)
        assertEquals(4, results.size)
    }

    @Test fun oldLogApiWithoutCursorFailsRatherThanPretendingToFollow() {
        assertEquals(2, DesktopCli.handleArgs(arrayOf("--json", "logs", "--follow"), printLine = {},
            requestCommand = { response(it, mapOf("entries" to ControlValue.ArrayValue(emptyList()))) }))
    }

    @Test fun interruptionStopsPollingWithoutSendingOwnerCancellation() {
        val emitted = java.util.concurrent.CountDownLatch(1)
        var exit: Int? = null
        var requests = 0
        val worker = Thread {
            exit = DesktopCli.handleArgs(arrayOf("--json", "status", "--watch"), printLine = { emitted.countDown() },
                requestCommand = { requests++; response(it) }, streamPause = { Thread.sleep(10_000) })
        }
        worker.start()
        try {
            assertTrue(emitted.await(2, java.util.concurrent.TimeUnit.SECONDS))
            worker.interrupt()
            worker.join(2000)
            assertFalse(worker.isAlive)
            assertEquals(130, exit)
            assertEquals(1, requests)
        } finally { worker.interrupt(); worker.join(2000) }
    }
}
