package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopLocationCliEndToEndTest {
    @Test
    fun terminalFileInputAndGuiEditsShareAnAuthenticatedDurableWorkspace() {
        val directory = Files.createTempDirectory("vpn-control-cli-東京")
        val store = DesktopStateStore(directory)
        val service = DesktopAppServiceFactory.createForTesting(store = store,
            initialWorkspace = DesktopWorkspace(PersistedState(), emptyList()))
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { service.executeCliCommand(it) } }, portFile = endpoint,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                val code = DesktopCli.handleArgs(args.toList().toTypedArray(), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Existing owner must be reused") })
                return code to lines.joinToString("\n")
            }
            assertEquals(0, invoke("source", "set", "current-locations").first)
            val input = directory.resolve("東京 office.json")
            Files.writeString(input, "socks://127.0.0.1:1080#First")
            assertEquals(0, invoke("locations", "add", "--input", input.toString()).first)
            assertTrue(invoke("locations", "list").second.contains("First"))
            assertEquals(0, invoke("select", "First").first)
            assertTrue(invoke("locations", "show", "First").second.contains("127.0.0.1"))
            val original = service.selectedDesktopLocation()!!
            service.saveLocation("socks://127.0.0.2:2080#GUI", original.index, original.rawLink).getOrThrow()
            assertTrue(invoke("locations", "list").second.contains("GUI"))
            Files.writeString(input, "socks://127.0.0.3:3080#CLI")
            assertEquals(0, invoke("locations", "update", "GUI", "--input", input.toString()).first)
            assertEquals("CLI", service.state.selectedProfileName)
            assertEquals("127.0.0.3", service.selectedDesktopLocation()!!.server)
            assertEquals(1, invoke("locations", "add", "--input", input.toString()).first)
            val loaded = DesktopStateStore(directory).loadWorkspace(DesktopWorkspace(PersistedState(), emptyList()))
            assertEquals("CLI", loaded.persistedState.selectedProfileName)
            assertEquals(1, loaded.locations.size)
            val exported = directory.resolve("locations export 東京.json")
            assertEquals(0, invoke("locations", "export", "--output", exported.toString()).first)
            assertEquals(0, invoke("locations", "delete", "CLI").first)
            assertTrue(DesktopStateStore(directory).loadWorkspace(DesktopWorkspace(PersistedState(), emptyList())).locations.isEmpty())
            assertEquals(0, invoke("locations", "import", "--input", exported.toString()).first)
            assertEquals(1, service.visibleDesktopLocations().size)
            assertEquals("CLI", service.visibleDesktopLocations().single().name)
            assertEquals(0, invoke("locations", "export", "--output", "-").first)
            val beforeInvalidImport = service.desktopLocations
            Files.writeString(input, "invalid location document")
            assertEquals(1, invoke("locations", "import", "--input", input.toString()).first)
            assertEquals(beforeInvalidImport, service.desktopLocations)
            assertFalse(service.state.isVpnRunning)
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun stdinIsConsumedAtClientAndReadFailuresNeverReachController() {
        var captured: DesktopCliCommand? = null
        val result = DesktopCli.handleArgs(arrayOf("locations", "add", "--input", "-"), printLine = {},
            requestCommand = { captured = it; DesktopCliResponse.success("saved") },
            readInput = { path -> assertEquals("-", path); Result.success("socks://127.0.0.1:1080#Local") })
        assertEquals(0, result)
        assertEquals(DesktopCliCommand.LocationSave("socks://127.0.0.1:1080#Local"), captured)
        assertEquals(1, DesktopCli.handleArgs(arrayOf("locations", "add", "--input", "missing"), printLine = {},
            requestCommand = { error("Unreadable input must fail before transport") },
            readInput = { Result.failure(java.io.IOException("private path")) }))
    }
}
