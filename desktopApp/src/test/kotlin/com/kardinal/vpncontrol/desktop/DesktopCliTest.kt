package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DesktopCliTest {
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
                DesktopCliResponse.success("VPN started.")
            },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(0, exitCode)
        assertEquals(DesktopCliCommand.On, command)
        assertEquals(listOf("VPN started."), lines)
    }

    @Test
    fun selectCommandJoinsRemainingArgsAsLocation() {
        var command: DesktopCliCommand? = null

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("select", "New", "York"),
            printLine = {},
            requestCommand = {
                command = it
                DesktopCliResponse.success("selected")
            },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(0, exitCode)
        assertEquals(DesktopCliCommand.Select("New York"), command)
    }

    @Test
    fun invalidCommandPrintsUsageAndFails() {
        val lines = mutableListOf<String>()

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("unknown"),
            printLine = lines::add,
            requestCommand = { error("request should not be sent") },
            startHeadlessController = { error("headless controller should not start") },
        )

        assertEquals(1, exitCode)
        assertEquals("Unknown command: unknown", lines.first())
        assertEquals(true, lines.last().contains("vpn-control find-best"))
    }

    @Test
    fun failedRequestReturnsResponseExitCode() {
        val lines = mutableListOf<String>()

        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("off"),
            printLine = lines::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = {
                DesktopCliResponse.failure("VPN Control desktop app is not running.", exitCode = 2)
            },
        )

        assertEquals(2, exitCode)
        assertEquals(listOf("VPN Control desktop app is not running."), lines)
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
                DesktopCliResponse.success("Best location selected: Berlin")
            },
        )

        assertEquals(0, exitCode)
        assertEquals(DesktopCliCommand.FindBest, startedCommand)
        assertEquals(listOf("Best location selected: Berlin"), lines)
    }

    @Test
    fun statusDoesNotStartAControllerWhenServiceIsUnavailable() {
        val lines = mutableListOf<String>()
        val exitCode = DesktopCli.handleArgs(
            args = arrayOf("status"),
            printLine = lines::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = { error("status must not start a controller") },
        )

        assertEquals(DesktopCliResponse.UNAVAILABLE_EXIT_CODE, exitCode)
        assertEquals(listOf(DesktopCliResponse.NOT_RUNNING_MESSAGE), lines)
    }
}
