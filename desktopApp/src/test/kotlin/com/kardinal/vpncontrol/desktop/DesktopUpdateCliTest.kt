package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertIs

class DesktopUpdateCliTest {
    @Test
    fun updateGrammarMapsToStrictProtocolCommands() {
        for ((name, expected) in mapOf("status" to ControlOperationId.UPDATES_STATUS,
            "check" to ControlOperationId.UPDATES_CHECK, "download" to ControlOperationId.UPDATES_DOWNLOAD,
            "dismiss" to ControlOperationId.UPDATES_DISMISS)) {
            assertEquals(0, DesktopCli.handleArgs(arrayOf("updates", name), {}, requestCommand = {
                val request = assertIs<DesktopCliCommand.ControlSubmit>(it).request
                assertEquals(expected, request.command.operation)
                assertEquals(it, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(it)).getOrThrow())
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner", request.requestId, ControlCode.OK, 0)))
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
        val owner = DesktopControllerOwner(service)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId))
        try {
            fun invoke(action: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf("updates", action), lines::add, printProgress = lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            val before = service.state
            val status = invoke("status")
            assertEquals(0, status.first)
            assertTrue(status.second.contains("checked: false"))
            val unavailable = invoke("download")
            assertEquals(1, unavailable.first, unavailable.second)
            assertTrue(unavailable.second.startsWith("RUNTIME_FAILED\n"), unavailable.second)
            assertEquals(before, service.state)
            assertEquals(0, invoke("dismiss").first)
            assertEquals(before.isVpnRunning, service.state.isVpnRunning)
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
