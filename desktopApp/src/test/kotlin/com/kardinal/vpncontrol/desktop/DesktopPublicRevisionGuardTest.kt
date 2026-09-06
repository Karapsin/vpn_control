package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopPublicRevisionGuardTest {
    @Test fun unsupportedJobGuardFailsBeforeDispatchAndPinnedReadKeepsItsData() {
        assertEquals(1, DesktopCli.handleArgs(arrayOf("--controller-id", "owner", "--if-revision", "0",
            "updates", "download"), printLine = {}, requestCommand = { error("Unsupported guard must not be ignored") }))
        val lines = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--controller-id", "owner", "settings", "show"),
            printLine = lines::add, requestCommand = {
                val request = (it as DesktopCliCommand.ControlSubmit).request
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult("owner", request.requestId,
                    ControlCode.OK, 4, data = mapOf("language" to ControlValue.Text("en")))))
            }))
        assertEquals(ControlValue.Text("en"), ControlProtocolCodec.decodeResult(lines.single()).data["language"])
    }

    @Test fun guardedCliWritesRejectStaleRevisionAndReplacementOwnerThroughAuthenticatedTransport() {
        val directory = Files.createTempDirectory("vpn-control-public-guard")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId))
        try {
            fun write(epoch: String, revision: Long, value: String): ControlResult {
                val lines = mutableListOf<String>()
                val code = DesktopCli.handleArgs(arrayOf("--json", "--controller-id", epoch,
                    "--if-revision", revision.toString(), "settings", "set", "validation.batch-size", value),
                    lines::add, requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Pinned requests cannot start a replacement owner") })
                return ControlProtocolCodec.decodeResult(lines.single()).also { assertEquals(it.exitCode, code) }
            }
            assertEquals(ControlCode.OK, write(owner.controllerId, 0, "17").code)
            assertEquals(ControlCode.CONFLICT, write(owner.controllerId, 0, "18").code)
            // Even a matching numeric revision from another epoch must not be rebound.
            assertEquals(ControlCode.CONFLICT, write("old-owner", 1, "18").code)
            assertEquals(17, service.state.validationSettings.batchSize)
            assertEquals(1L, service.configurationRevision)
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun pinnedHumanAndJsonRequestsDoNotBootstrapAndCarryBothGuards() {
        for (json in listOf(false, true)) {
            val lines = mutableListOf<String>()
            assertEquals(2, DesktopCli.handleArgs((if (json) listOf("--json") else emptyList()).plus(listOf(
                "settings", "set", "language", "en", "--controller-id", "owner", "--if-revision", "7")).toTypedArray(),
                lines::add, requestCommand = {
                    val request = (it as DesktopCliCommand.ControlSubmit).request
                    assertEquals("owner", request.controllerId)
                    assertEquals(7L, request.ifRevision)
                    DesktopCliResponse.notRunning()
                }, startHeadlessController = { error("No replacement for a pinned owner") }))
            if (json) assertEquals(ControlCode.UNAVAILABLE, ControlProtocolCodec.decodeResult(lines.single()).code)
            else assertEquals("UNAVAILABLE", lines.single())
        }
    }
}
