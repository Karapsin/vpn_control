package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DesktopCliTest {
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
            requestCommand = { DesktopCliResponse.failure("VPN Control desktop app is not running.", exitCode = 2) },
        )

        assertEquals(2, exitCode)
        assertEquals(listOf("VPN Control desktop app is not running."), lines)
    }
}
