package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopCliStreamEndToEndTest {
    @Test fun authenticatedFollowReportsRolloverThenDrainsEveryRetainedEntryOnce() {
        val root = Files.createTempDirectory("follow-owner")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(root), DesktopWorkspace(PersistedState(), emptyList()))
        val owner = DesktopControllerOwner(service)
        val endpoint = root.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, controllerId = owner.controllerId, portFile = endpoint))
        try {
            val lines = mutableListOf<String>()
            var polls = 0
            assertEquals(130, DesktopCli.handleArgs(arrayOf("--json", "logs", "--follow", "--limit", "0"), printLine = lines::add,
                requestCommand = { polls++; DesktopActivationServer.requestCliCommand(it, endpoint) },
                startHeadlessController = { error("Reuse owner") }, streamActive = { polls < 3 }, streamPause = {
                    if (polls == 1) repeat(220) { service.postStatus("repeat") }
                }))
            val results = lines.map(ControlProtocolCodec::decodeResult)
            assertEquals(4, results.size)
            assertTrue("LOG_HISTORY_GAP" in results[1].warnings)
            val entries = results.dropLast(1).flatMap { (it.data["entries"] as ControlValue.ArrayValue).values }
            val ids = entries.map { ((it as ControlValue.ObjectValue).values["id"] as ControlValue.Text).value }
            assertEquals(200, entries.size)
            assertEquals(200, ids.distinct().size)
            assertTrue(results.all { it.controllerId == owner.controllerId })
            assertFalse(service.state.isVpnRunning)
        } finally { server.close(); owner.close(); root.toFile().deleteRecursively() }
    }

    @Test fun replacingAuthenticatedEndpointDoesNotRetargetWatch() {
        val root = Files.createTempDirectory("watch-owner")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val first = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(root.resolve("one")), empty))
        val second = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(root.resolve("two")), empty))
        val endpoint = root.resolve("activation.port")
        fun server(owner: DesktopControllerOwner) = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS }, onCliCommand = { runBlocking { owner.session.execute(it) } },
            controllerId = owner.controllerId, portFile = endpoint))
        val original = server(first)
        var replacement: DesktopActivationServer? = null
        try {
            val lines = mutableListOf<String>()
            assertEquals(1, DesktopCli.handleArgs(arrayOf("--json", "status", "--watch"), printLine = lines::add,
                requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                startHeadlessController = { error("Do not spawn or rebind") }, streamPause = {
                    original.close()
                    replacement = server(second)
                }))
            val results = lines.map(ControlProtocolCodec::decodeResult)
            assertEquals(first.controllerId, results.first().controllerId)
            assertEquals(ControlCode.CONFLICT, results.last().code)
            assertEquals(2, results.size)
        } finally { replacement?.close(); original.close(); first.close(); second.close(); root.toFile().deleteRecursively() }
    }
}
