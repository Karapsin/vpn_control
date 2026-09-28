package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertIs

class DesktopUpdateCliTest {
    @Test
    fun transportProbeRequiresObservedOwnerAndNeverStartsOne() {
        val correlation = "11111111-1111-4111-8111-111111111111"
        val output = mutableListOf<String>()
        val noOwner = DesktopCli.handleArgs(arrayOf("--controller-id", "observed-owner", "--json",
            "updates", "transport-probe", correlation), printLine = output::add,
            requestCommand = { DesktopCliResponse.notRunning() },
            startHeadlessController = { error("Probe must not launch a controller") })
        assertEquals(2, noOwner)
        assertTrue(output.joinToString().contains("UNAVAILABLE"))
        assertEquals(1, DesktopCli.handleArgs(arrayOf("updates", "transport-probe", correlation),
            printLine = {}, requestCommand = { error("Missing owner identity must fail before transport") },
            startHeadlessController = { error("No startup") }))
        assertEquals(1, DesktopCli.handleArgs(arrayOf("--controller-id", "observed-owner",
            "updates", "transport-probe", "not-a-uuid"), printLine = {},
            requestCommand = { error("Invalid UUID must fail before transport") },
            startHeadlessController = { error("No startup") }))
    }

    @Test
    fun authenticatedOwnerReturnsOnlyBoundedProbeEvidence() = runBlocking {
        val correlation = "11111111-1111-4111-8111-111111111111"
        var calls = 0
        val session = DesktopHeadlessSession(CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
            { com.kardinal.vpncontrol.MainUiState() }, { error("No unrelated command") }, {}, controllerId = "owner",
            probeUpdateTransport = { id ->
                calls++
                assertEquals(correlation, id)
                Result.success(DesktopUpdateTransportProbe(id, "a".repeat(64), "b".repeat(64),
                    16800, "2.2.0", "c".repeat(64), 123L))
            })
        try {
            fun request(owner: String, id: String = correlation) = com.kardinal.vpncontrol.model.ControlRequest(
                "request", com.kardinal.vpncontrol.model.ControlCommand(ControlOperationId.UPDATES_TRANSPORT_PROBE,
                    mapOf("correlation-id" to com.kardinal.vpncontrol.model.ControlValue.Text(id))),
                controllerId = owner)
            assertEquals("CONFLICT", session.execute(DesktopCliCommand.ControlSubmit(request("other"))).let {
                com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(it.message).code.wireName
            })
            assertEquals(0, calls)
            val result = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
                session.execute(DesktopCliCommand.ControlSubmit(request("owner"))).message)
            assertEquals("OK", result.code.wireName)
            assertEquals("owner", result.controllerId)
            assertEquals(correlation, (result.data["correlationId"] as com.kardinal.vpncontrol.model.ControlValue.Text).value)
            assertEquals(1, calls)
            assertTrue(result.data.keys == setOf("correlationId", "manifestSha256", "peerCertificateSha256",
                "manifestBuildNumber", "availableVersion", "assetSha256", "assetSizeBytes"))
        } finally { session.close() }
    }
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
