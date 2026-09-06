package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopFrontendClientTest {
    @Test
    fun clientUsesOnlyTypedSessionAndRefusesActionsOnRetainedUnavailableFrame() = runTest {
        val requests = mutableListOf<ControlRequest>()
        val session = object : ControlSession {
            override val snapshots = MutableStateFlow(ControlSnapshot("owner", 5, null, null, AppMode.PROXY_ONLY,
                null, null, null, false))
            override suspend fun submit(request: ControlRequest): ControlResult {
                requests += request
                return ControlResult("owner", request.requestId, ControlCode.OK, 5)
            }
            override suspend fun operation(id: String): ControlOperation? = null
            override suspend fun cancelOperation(id: String) = ControlResult("owner", id, ControlCode.NOT_FOUND, 5)
        }
        val failure = MutableStateFlow<ControlCode?>(null)
        val client = DesktopFrontendClient(session, MutableStateFlow(null), failure)
        assertTrue(client.execute(DesktopCliCommand.LocationBenchmark("", configurationId = "opaque-row")).success)
        assertEquals(ControlCommand(ControlOperationId.LOCATIONS_BENCHMARK,
            mapOf("id" to ControlValue.Text("opaque-row"))), requests.single().command)
        assertEquals("owner", requests.single().controllerId)
        failure.value = ControlCode.UNAVAILABLE
        val result = client.read(ControlOperationId.ON)
        assertEquals(ControlCode.UNAVAILABLE, result.code)
        assertFalse(result.final)
        assertEquals(1, requests.size)
    }

    @Test
    fun independentRoutingDraftsKeepLocalInputAndLostResponseRetryIdentity() = runTest {
        val directory = Files.createTempDirectory("vpn-control-frontend-routing")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            suspend fun open() = DesktopFrontendRoutingDraft.from(owner.submit(ControlRequest(
                java.util.UUID.randomUUID().toString(), ControlCommand(ControlOperationId.ROUTING_SHOW), controllerId = owner.controllerId)))
            val a = open().copy(domains = "one.example")
            val b = open().copy(domains = "two.example")
            assertTrue(service.state.routingRules.directDomainSuffixes.isEmpty())
            assertEquals(a.request(), a.request())
            assertNotEquals(a.request().requestId, a.copy(domains = "edited.example").request().requestId)
            val saved = owner.submit(a.request())
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(saved, owner.submit(a.request()))
            assertEquals(ControlCode.CONFLICT, owner.submit(b.request()).code)
            assertEquals("two.example", b.domains)
            assertEquals(listOf("one.example"), service.state.routingRules.directDomainSuffixes)
            assertNotEquals(b.request().requestId, open().copy(domains = b.domains).request().requestId)
            assertFalse(b.toString().contains("two.example"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun safeFrameProjectionKeepsActualSettingsAndExplicitLogEntries() {
        val directory = Files.createTempDirectory("vpn-control-frontend-projection")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            service.applyControlSettings(mapOf("language" to ControlValue.Text("en"), "refresh.policy" to ControlValue.Text("custom"),
                "refresh.custom-hours" to ControlValue.DecimalValue(2.5))).getOrThrow()
            val frame = service.controlPresentationSnapshot("owner")
            val ui = frame.toFrontendUiState()
            assertEquals(AppLanguage.ENGLISH, ui.appLanguage)
            assertEquals(SubscriptionRefreshPolicy.CUSTOM, ui.subscriptionRefreshPolicy)
            assertEquals(2.5, ui.subscriptionRefreshCustomHours)
            assertTrue(ui.subscriptions.isEmpty()) // subscription render rows come from typed projection, not fake URLs
            val result = ControlResult("owner", "logs", ControlCode.OK, 0, data = mapOf("entries" to ControlValue.ArrayValue(listOf(
                ControlValue.ObjectValue(mapOf("id" to ControlValue.Text("log-1"), "message" to ControlValue.Text("Disconnected"),
                    "createdAtEpochMillis" to ControlValue.IntegerValue(123)))))))
            assertEquals(listOf(ConnectionLogEntry("log-1", "Disconnected", 123)), desktopFrontendLogs(result))
            assertFails { desktopFrontendLogs(result.copy(data = emptyMap())) }
        } finally { directory.toFile().deleteRecursively() }
    }
}
