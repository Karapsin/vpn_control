package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopConfigurationResultDataTest {
    @Test fun committedRoutingResultCannotBeReplacedByALaterWriter() = runTest {
        val directory = Files.createTempDirectory("routing-own-result")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val session = DesktopHeadlessSession(backgroundScope, { service.state }, service::executeCliCommand, {},
            metadataProvider = service::controlMetadata, mutateConfiguration = { command, revision ->
                val result = service.mutateControlConfiguration(command, revision)
                service.setControlRouting("direct-domains", "later.example").getOrThrow()
                result
            })
        try {
            val request = ControlRequest("routing-own-result", ControlCommand(ControlOperationId.ROUTING_SET,
                mapOf("key" to ControlValue.Text("direct-domains"), "value" to ControlValue.Text("[\"*.EXAMPLE.com.\"]"))),
                controllerId = session.controllerId, ifRevision = 0)
            fun decode(response: DesktopCliResponse) = ControlProtocolCodec.decodeResult(response.message)
            val result = decode(session.execute(DesktopCliCommand.ControlSubmit(request)))
            assertEquals(ControlCode.OK, result.code)
            assertEquals(1L, result.configurationRevision)
            assertEquals(2L, service.configurationRevision)
            assertEquals(mapOf("direct-domains" to ControlValue.ArrayValue(listOf(ControlValue.Text("example.com")))), result.data)
            assertEquals(listOf("later.example"), service.state.routingRules.directDomainSuffixes)
            assertEquals(result, decode(session.execute(DesktopCliCommand.ControlSubmit(request))))
        } finally { session.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun routingImportReportsCommittedValuesAndUnsupportedAppAssignmentsWithoutPackageNames() = runTest {
        val directory = Files.createTempDirectory("routing-import-result")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val raw = RoutingRulesTransfer.export(RoutingRules(ignoreRules = true, blockQuicUdp443 = true,
                proxyPackages = listOf("private.package"), directDomainSuffixes = listOf("example.com"))).content
            val result = owner.submit(ControlRequest("routing-import-result", ControlCommand(ControlOperationId.ROUTING_IMPORT,
                mapOf("input" to ControlValue.Text(raw))), controllerId = owner.controllerId))
            assertEquals(ControlCode.OK, result.code)
            assertEquals(ControlValue.BooleanValue(true), result.data["ignore-rules"])
            assertEquals(ControlValue.BooleanValue(true), result.data["block-quic-udp443"])
            assertEquals(listOf("ROUTING_APP_ASSIGNMENTS_UNSUPPORTED"), result.warnings)
            assertEquals(ControlValue.ArrayValue(listOf(ControlValue.Text("proxyPackages"))), result.data["unsupportedFields"])
            assertFalse(result.data.toString().contains("private.package"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun resultRetentionRejectsArbitraryImportContentExtraFieldsAndWrongTypes() {
        for ((operation, raw) in listOf(
            ControlOperationId.LOCATIONS_IMPORT to "{\"importedLocations\":-1}",
            ControlOperationId.LOCATIONS_IMPORT to "{\"input\":\"private-profile\"}",
            ControlOperationId.ROUTING_SET to "{\"direct-domains\":\"private-profile\"}",
            ControlOperationId.ROUTING_SET to "{\"ignore-rules\":true,\"input\":\"private-profile\"}",
            ControlOperationId.ROUTING_IMPORT to "{\"ignore-rules\":false,\"block-quic-udp443\":false,\"direct-domains\":[],\"unsupportedFields\":[\"private-path\"]}"
        )) assertFails { DesktopConfigurationResultData.decode(operation, raw) }
    }
}
