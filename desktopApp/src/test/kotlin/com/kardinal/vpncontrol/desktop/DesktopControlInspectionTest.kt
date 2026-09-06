package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopControlInspectionTest {
    @Test fun explicitFrontendLocationReadNeverReinterpretsIdentityAsASelector() = runBlocking {
        val directory = Files.createTempDirectory("stable-location-read")
        val raw = listOf("socks://127.0.0.1:1080#Other", "socks://user:PRIVATE@127.0.0.2:1080#1")
        val records = raw.toDesktopLocationRecords(1)
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), DesktopWorkspace(
            PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS, currentLocations = raw, savedLocations = raw), records))
        val owner = DesktopControllerOwner(service)
        try {
            val id = assertNotNull(service.controlLocationId(service.visibleDesktopLocations()[1]))
            suspend fun read(arguments: Map<String, ControlValue> = mapOf("id" to ControlValue.Text(id)), epoch: String = owner.controllerId) =
                ControlProtocolCodec.decodeResult(owner.session.execute(DesktopCliCommand.ControlSubmit(ControlRequest(
                    java.util.UUID.randomUUID().toString(), ControlCommand(ControlOperationId.LOCATIONS_SHOW, arguments),
                    controllerId = epoch))).message)
            val before = read()
            assertEquals(ControlCode.OK, before.code)
            assertEquals(ControlValue.Text(id), before.data["id"])
            assertEquals(ControlValue.Text(com.kardinal.vpncontrol.data.LocationConfigs.prettyStoredLocation(raw[1])), before.data["configuration"])
            assertEquals(ControlCode.INVALID_ARGUMENT, read(mapOf("id" to ControlValue.Text(id), "selector" to ControlValue.Text("1"))).code)
            assertEquals(ControlCode.CONFLICT, read(epoch = "previous-owner").code)
            service.deleteLocation(service.visibleDesktopLocations().first().index).getOrThrow()
            val reordered = read()
            assertEquals(ControlCode.OK, reordered.code)
            assertEquals(before.data, reordered.data)
            assertEquals(service.configurationRevision, reordered.configurationRevision)
            service.deleteLocation(service.visibleDesktopLocations().first().index).getOrThrow()
            val removed = read()
            assertEquals(ControlCode.CONFLICT, removed.code)
            assertFalse(ControlProtocolCodec.encodeResult(removed).contains("PRIVATE"))
            assertTrue(owner.session.operationSnapshot().isEmpty())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun publicJsonInspectionUsesVisibleSelectionAndPreservesOnlyExplicitConfiguration() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-inspection-東京")
        val records = listOf("socks://127.0.0.1:1080#Same", "socks://127.0.0.2:2080#Same").toDesktopLocationRecords(1)
        val source = "https://example.test/sub?token=synthetic-secret"
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                currentLocations = records.map { it.rawLink }, savedLocations = records.map { it.rawLink },
                subscriptions = listOf(SubscriptionSource(id = "sub", url = source, customName = "Source"))), records))
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                val exit = DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Existing owner required") })
                return exit to lines.single()
            }
            fun json(vararg args: String, code: ControlCode = ControlCode.OK): ControlResult {
                val response = invoke("--json", *args)
                assertEquals(code.exitCode, response.first, response.second)
                return ControlProtocolCodec.decodeResult(response.second).also {
                    assertEquals(code, it.code)
                    assertEquals(owner.controllerId, it.controllerId)
                    assertEquals(0L, it.configurationRevision)
                    assertTrue(it.final)
                }
            }
            val before = service.state
            val locations = json("locations", "list")
            assertFalse(ControlProtocolCodec.encodeResult(locations).contains("127.0.0"))
            val rows = (locations.data.getValue("locations") as ControlValue.ArrayValue).values
            assertEquals(2, rows.size)
            assertEquals(ControlValue.IntegerValue(2), (rows[1] as ControlValue.ObjectValue).values["index"])
            assertEquals(ControlValue.Text(invoke("locations", "show", "2").second),
                json("locations", "show", "2").data["configuration"])
            json("locations", "show", "Same", code = ControlCode.AMBIGUOUS_LOCATION)
            json("locations", "show", "missing", code = ControlCode.NOT_FOUND)
            assertFalse(ControlProtocolCodec.encodeResult(json("subscriptions", "list")).contains("synthetic-secret"))
            assertEquals(ControlValue.Text(source), json("subscriptions", "show", "sub").data["source"])
            json("subscriptions", "show", "missing", code = ControlCode.NOT_FOUND)
            val routing = (json("routing", "show").data.getValue("routing") as ControlValue.ObjectValue).values
            // Both use the v7 export representation; independent reads have distinct export timestamps.
            assertEquals(ControlProtocolCodec.decodeValues(invoke("routing", "show").second) - "exported_at",
                routing - "exported_at")
            assertEquals(service.state.routingRules,
                com.kardinal.vpncontrol.data.RoutingRulesTransfer.import(ControlProtocolCodec.encodeValues(routing)))
            assertEquals(mapOf("present" to ControlValue.BooleanValue(false)), json("ssh", "key", "status").data)
            assertEquals(ControlProtocolCodec.decodeValues(invoke("updates", "status").second), json("updates", "status").data)
            val malformed = owner.session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("malformed",
                ControlCommand(ControlOperationId.LOCATIONS_SHOW, mapOf("selector" to ControlValue.IntegerValue(1))),
                controllerId = owner.controllerId)))
            assertEquals(ControlCode.INVALID_ARGUMENT, ControlProtocolCodec.decodeResult(malformed.message).code)
            assertEquals(before, service.state)
            assertTrue(owner.session.operationSnapshot().isEmpty())
        } finally {
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
