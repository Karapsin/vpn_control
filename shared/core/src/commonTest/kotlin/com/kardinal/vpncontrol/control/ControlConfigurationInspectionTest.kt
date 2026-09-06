package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlConfigurationInspectionTest {
    @Test fun exportsUseGuiTransferFormatsAndRejectDeviceSideDestinationArguments() {
        val locations = listOf("socks://user:SECRET@127.0.0.1:1080")
        val state = MainUiState(currentLocations = locations)
        val result = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.LOCATIONS_EXPORT), 0).getOrThrow()
        assertEquals(ControlValue.Text(com.kardinal.vpncontrol.data.LocationConfigs.export(
            locations, "1970-01-01T00:00:00Z").content), result["content"])
        val routing = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.ROUTING_EXPORT), 0).getOrThrow()
        assertEquals(state.routingRules, RoutingRulesTransfer.import((routing.getValue("content") as ControlValue.Text).value))
        val failure = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.ROUTING_EXPORT,
            mapOf("output" to ControlValue.Text("private-device-path"))), 0).exceptionOrNull() as ControlProtocolException
        assertEquals(ControlCode.INVALID_ARGUMENT, failure.code)
        assertEquals(ControlCode.NOT_FOUND, (ControlConfigurationInspection.read(MainUiState(),
            ControlCommand(ControlOperationId.LOCATIONS_EXPORT), 0).exceptionOrNull() as ControlProtocolException).code)
    }
    private val source = SubscriptionSource(id = "source", url = "https://private.example/?token=SECRET", customName = "Work",
        cachedLocations = listOf("socks://user:SECRET@127.0.0.1:1080"))
    private val state = MainUiState(subscriptions = listOf(source), routingRules = RoutingRules(ignoreRules = true,
        proxyPackages = listOf("app.browser"), directDomainSuffixes = listOf("example.com")))

    @Test fun listRedactsConfigurationWhileExplicitShowPreservesUsableSource() {
        val listed = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.SUBSCRIPTIONS_LIST), 0).getOrThrow()
        assertFalse(ControlProtocolCodec.encodeValues(listed).contains("SECRET"))
        val rows = (listed.getValue("subscriptions") as ControlValue.ArrayValue).values
        assertEquals(ControlValue.IntegerValue(1), (rows.single() as ControlValue.ObjectValue).values["cachedLocations"])
        val shown = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.SUBSCRIPTIONS_SHOW,
            mapOf("id" to ControlValue.Text(source.id))), 0).getOrThrow()
        assertEquals(ControlValue.Text(source.url), shown["source"])
        assertFalse(shown.toString().contains("socks://"))
    }

    @Test fun routingInspectionIsTheSameCurrentTransferSchemaWithDeterministicTimestamp() {
        val result = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.ROUTING_SHOW), 0).getOrThrow()
        val routing = (result.getValue("routing") as ControlValue.ObjectValue).values
        assertEquals(state.routingRules, RoutingRulesTransfer.import(ControlProtocolCodec.encodeValues(routing)))
        assertEquals(ControlValue.Text("1970-01-01T00:00:00Z"), routing["exported_at"])
    }

    @Test fun missingAndMalformedIdsHaveStableCodesWithoutEchoingInputs() {
        for ((args, expected) in listOf(
            emptyMap<String, ControlValue>() to ControlCode.INVALID_ARGUMENT,
            mapOf("id" to ControlValue.Null) to ControlCode.INVALID_ARGUMENT,
            mapOf("id" to ControlValue.Text("SECRET")) to ControlCode.NOT_FOUND,
            mapOf("id" to ControlValue.Text(source.id), "private" to ControlValue.Text("SECRET")) to ControlCode.INVALID_ARGUMENT
        )) {
            val failure = ControlConfigurationInspection.read(state, ControlCommand(ControlOperationId.SUBSCRIPTIONS_SHOW, args), 0).exceptionOrNull()
            assertEquals(expected, (failure as ControlProtocolException).code)
            assertFalse(failure.message.orEmpty().contains("SECRET"))
        }
    }
}
