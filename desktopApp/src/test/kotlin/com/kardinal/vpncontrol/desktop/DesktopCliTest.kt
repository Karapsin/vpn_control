package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertIs
import kotlin.test.assertTrue
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*

class DesktopCliTest {
    private fun success(command: DesktopCliCommand, message: String): DesktopCliResponse {
        val request = assertIs<DesktopCliCommand.ControlSubmit>(command).request
        return DesktopCliResponse.success(ControlDocumentCodec.encodeResult(
            ControlResult("owner", request.requestId, ControlCode.OK, 0, message = message)))
    }
    @Test
    fun helpVersionAndUnknownOptionsNeverContactOrStartAController() {
        for ((args, expected) in listOf(
            arrayOf("--help") to 0, arrayOf("help") to 0, arrayOf("--version") to 0,
            arrayOf("--typo") to 1, arrayOf("--tray", "--typo") to 1,
        )) {
            assertEquals(expected, DesktopCli.handleArgs(args, printLine = {},
                requestCommand = { error("No controller access expected") },
                startHeadlessController = { error("No controller startup expected") }))
        }
    }

    @Test
    fun nonCliArgsAreIgnored() {
        assertNull(DesktopCli.handleArgs(emptyArray(), printLine = {}))
        assertNull(DesktopCli.handleArgs(arrayOf("--tray"), printLine = {}))
    }

    @Test
    fun onCommandSendsRequestAndPrintsResponse() {
        val lines = mutableListOf<String>()
        var command: DesktopCliCommand? = null

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("on"),
            printLine = lines::add,
            requestCommand = {
                command = it
                success(it, "VPN started.")
            },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(0, exitCode)
        assertEquals(ControlOperationId.ON, assertIs<DesktopCliCommand.ControlSubmit>(command).request.command.operation)
        assertTrue(lines.single().contains("VPN started."))
    }

    @Test
    fun selectCommandJoinsRemainingArgsAsLocation() {
        var command: DesktopCliCommand? = null

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("select", "New", "York"),
            printLine = {},
            requestCommand = {
                command = it
                success(it, "selected")
            },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(0, exitCode)
        val typed = assertIs<DesktopCliCommand.ControlSubmit>(command).request.command
        assertEquals(ControlOperationId.LOCATIONS_SELECT, typed.operation)
        assertEquals(ControlValue.Text("New York"), typed.arguments["selector"])
    }

    @Test
    fun invalidCommandReportsFailureOnStderr() {
        val lines = mutableListOf<String>()

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("unknown"),
            printLine = { error("No stdout for failure") }, printProgress = lines::add,
            requestCommand = { error("request should not be sent") },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(1, exitCode)
        assertTrue(lines.single().startsWith("INVALID_ARGUMENT"))
    }

    @Test
    fun failedRequestReturnsResponseExitCode() {
        val lines = mutableListOf<String>()

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("off"),
            printLine = { error("No stdout for failure") }, printProgress = lines::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = {
                DesktopCliResponse.failure("VPN Control desktop app is not running.", exitCode = 2)
            },
        )

        assertEquals(2, exitCode)
        assertTrue(lines.single().startsWith("UNAVAILABLE"))
    }

    @Test
    fun missingServerStartsHeadlessControllerAndPrintsResponse() {
        val lines = mutableListOf<String>()
        var startedCommand: DesktopCliCommand? = null

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("find-best"),
            printLine = lines::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = {
                startedCommand = it
                success(it, "Best location selected: Berlin")
            },
        )

        assertEquals(0, exitCode)
        assertEquals(ControlOperationId.FIND_BEST, assertIs<DesktopCliCommand.ControlSubmit>(startedCommand).request.command.operation)
        assertTrue(lines.single().contains("Best location selected: Berlin"))
    }

    @Test
    fun statusDoesNotStartAControllerWhenServiceIsUnavailable() {
        val lines = mutableListOf<String>()
        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("status"),
            printLine = { error("No stdout for failure") }, printProgress = lines::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = { error("status must not start a controller") },
        )

        assertEquals(DesktopCliResponse.UNAVAILABLE_EXIT_CODE, exitCode)
        assertTrue(lines.single().startsWith("UNAVAILABLE"))
    }
}
