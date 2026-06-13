package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopActivationServerTest {
    @Test
    fun requestShowInvokesHandler() {
        val tempDir = Files.createTempDirectory("vpn-control-activation-show")
        try {
            var showRequests = 0
            val portFile = tempDir.resolve("activation.port")
            val server = DesktopActivationServer.start(
                onShowWindow = { showRequests += 1 },
                portFile = portFile,
            )
            assertNotNull(server)
            server.use {
                assertTrue(DesktopActivationServer.requestShow(portFile = portFile))
                assertEquals(1, showRequests)
            }
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun cliCommandRoundTripsThroughActivationServer() {
        val tempDir = Files.createTempDirectory("vpn-control-activation-cli")
        try {
            var command: DesktopCliCommand? = null
            val portFile = tempDir.resolve("activation.port")
            val server = DesktopActivationServer.start(
                onShowWindow = {},
                onCliCommand = {
                    command = it
                    DesktopCliResponse.success("Selected location: New York")
                },
                portFile = portFile,
            )
            assertNotNull(server)
            server.use {
                val response = DesktopActivationServer.requestCliCommand(
                    command = DesktopCliCommand.Select("New York"),
                    portFile = portFile,
                )

                assertTrue(response.success)
                assertEquals(0, response.exitCode)
                assertEquals("Selected location: New York", response.message)
                assertEquals(DesktopCliCommand.Select("New York"), command)
            }
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun missingActivationServerReturnsNotRunningResponse() {
        val tempDir = Files.createTempDirectory("vpn-control-activation-missing")
        try {
            val response = DesktopActivationServer.requestCliCommand(
                command = DesktopCliCommand.Off,
                portFile = tempDir.resolve("activation.port"),
            )

            assertFalse(response.success)
            assertEquals(2, response.exitCode)
            assertEquals("VPN Control desktop app is not running.", response.message)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
