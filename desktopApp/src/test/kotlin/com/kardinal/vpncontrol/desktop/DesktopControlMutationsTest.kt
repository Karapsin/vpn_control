package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopControlMutationsTest {
    @Test
    fun publicJsonWritesPersistThroughExistingActionsAndRetriedRequestsDoNotRepeat() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-json-writes-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val store = DesktopStateStore(directory)
        val service = DesktopAppServiceFactory.createForTesting(store, empty)
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId))
        var input = ""
        var lastRequest: DesktopCliCommand.ControlSubmit? = null
        try {
            fun invoke(vararg args: String, code: ControlCode = ControlCode.OK): ControlResult {
                val lines = mutableListOf<String>()
                val exit = DesktopCli.handleArgs(arrayOf("--json", *args), lines::add,
                    requestCommand = {
                        lastRequest = it as DesktopCliCommand.ControlSubmit
                        DesktopActivationServer.requestCliCommand(it, endpoint)
                    }, startHeadlessController = { error("Existing owner required") },
                    readInput = { assertEquals("client-only.txt", it); Result.success(input) })
                assertEquals(code.exitCode, exit, lines.joinToString())
                return ControlProtocolCodec.decodeResult(lines.single()).also {
                    assertEquals(code, it.code)
                    assertEquals(code != ControlCode.ACCEPTED, it.final)
                    assertFalse(lines.single().contains("synthetic-secret"))
                }
            }
            invoke("source", "set", "current-locations")
            input = "socks://127.0.0.1:1080#First"
            val added = invoke("locations", "add", "--input", "client-only.txt")
            val sent = requireNotNull(lastRequest)
            assertEquals(ControlValue.Text(input), sent.request.command.arguments["input"])
            assertFalse(ControlProtocolCodec.encodeRequest(sent.request).contains("client-only.txt"))
            val retained = ControlProtocolCodec.decodeResult(DesktopActivationServer.requestCliCommand(sent, endpoint).message)
            assertEquals(added, retained)
            assertEquals(1, service.visibleDesktopLocations().size)
            assertEquals(added.configurationRevision, service.configurationRevision)
            invoke("select", "First")
            invoke("select", "missing-synthetic-secret", code = ControlCode.NOT_FOUND)
            input = "socks://127.0.0.2:2080#Edited"
            invoke("locations", "update", "First", "--input", "client-only.txt")
            assertEquals("Edited", service.selectedDesktopLocation()?.name)
            input = com.kardinal.vpncontrol.data.LocationConfigs.export(listOf("socks://127.0.0.3:3080#Imported")).content
            invoke("locations", "import", "--input", "client-only.txt")
            assertTrue(service.visibleDesktopLocations().any { it.name == "Imported" })
            invoke("locations", "delete", "Imported")
            invoke("locations", "delete", "missing", code = ControlCode.NOT_FOUND)
            invoke("routing", "set", "ignore-rules", "true")
            assertTrue(service.state.routingRules.ignoreRules)
            input = "{\"ignore_rules\":false,\"direct_domain_suffixes\":[\"Example.COM\"]}"
            invoke("routing", "import", "--input", "client-only.txt")
            assertEquals(listOf("example.com"), service.state.routingRules.directDomainSuffixes)
            invoke("routing", "set", "ignore-rules", "not-bool", code = ControlCode.INVALID_ARGUMENT)
            input = "https://example.test/sub?token=synthetic-secret"
            val subscription = invoke("--async", "subscriptions", "add", "--input", "client-only.txt", "--name", "Source",
                code = ControlCode.ACCEPTED)
            invoke("operations", "wait", requireNotNull(subscription.operationId))
            val id = service.state.subscriptions.single().id
            invoke("subscriptions", "update", id, "--name", "Renamed")
            invoke("source", "set", "subscription", id)
            assertEquals(id, service.state.activeSubscriptionId)
            invoke("subscriptions", "add", "--source", "https://second.example.test/sub", "--name", "Second source")
            val secondId = service.state.subscriptions.single { it.id != id }.id
            invoke("source", "set", "all")
            assertEquals(ALL_SUBSCRIPTIONS_ID, service.state.activeSubscriptionId)
            invoke("subscriptions", "delete", id)
            invoke("subscriptions", "delete", secondId)
            assertTrue(service.state.subscriptions.isEmpty())
            input = "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-secret\n-----END OPENSSH PRIVATE KEY-----\n"
            invoke("ssh", "key", "import", "--input", "client-only.txt")
            assertTrue(service.hasHomeSshPrivateKey())
            assertFalse(Files.readString(directory.resolve("workspace.json")).contains("synthetic-secret"))
            invoke("updates", "dismiss")
            assertEquals(service.state.routingRules, store.loadWorkspace(empty).persistedState.routingRules)
            val revision = service.configurationRevision
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            invoke("routing", "set", "ignore-rules", "true", code = ControlCode.PERSISTENCE_FAILED)
            assertEquals(revision, service.configurationRevision)
            assertFalse(service.state.routingRules.ignoreRules)
        } finally {
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
