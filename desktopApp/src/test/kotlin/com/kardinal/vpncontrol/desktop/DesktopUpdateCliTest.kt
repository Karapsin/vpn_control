package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopUpdateCliTest {
    @Test
    fun updateGrammarMapsToStrictProtocolCommands() {
        for ((name, expected) in mapOf("status" to DesktopCliCommand.UpdatesStatus,
            "check" to DesktopCliCommand.UpdatesCheck, "download" to DesktopCliCommand.UpdatesDownload,
            "dismiss" to DesktopCliCommand.UpdatesDismiss)) {
            assertEquals(0, DesktopCli.handleArgs(arrayOf("updates", name), {}, requestCommand = {
                assertEquals(expected, it)
                assertEquals(it, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(it)).getOrThrow())
                DesktopCliResponse.success("ok")
            }, startHeadlessController = { error("No startup") }))
        }
        assertEquals(1, DesktopCli.handleArgs(arrayOf("updates", "check", "--unknown"), {},
            requestCommand = { error("Invalid input must not dispatch") }))
    }

    @Test
    fun authenticatedUpdateStatusAndUnavailableDownloadDoNotChangeRuntime() {
        val directory = Files.createTempDirectory("vpn-control-update-cli")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { service.executeCliCommand(it) } }, portFile = endpoint))
        try {
            fun invoke(action: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf("updates", action), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            val before = service.state
            val status = invoke("status")
            assertEquals(0, status.first)
            assertTrue(status.second.contains("\"checked\":false"))
            assertEquals(1 to "NO_UPDATE_AVAILABLE", invoke("download"))
            assertEquals(before, service.state)
            assertEquals(0, invoke("dismiss").first)
            assertEquals(before.isVpnRunning, service.state.isVpnRunning)
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }
}
