package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.*
import kotlin.test.*

class DesktopPresentationSnapshotTest {
    @Test fun authenticatedPresentationIsCoherentAndExcludesPrivateConfigurationAndDrafts() = runBlocking {
        val directory = Files.createTempDirectory("frontend-presentation")
        val raw = "socks://user:PROFILE_PASSWORD@127.0.0.1:1080#Public"
        val persisted = PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(raw), selectedProfileName = "Public", selectedProfileRawLink = raw,
            selectedProfileServer = "127.0.0.1",
            dnsSettings = DnsSettings(DnsMode.CUSTOM_DOH, "https://private-dns.example/dns-query"),
            homeSshRouteSettings = HomeSshRouteSettings(host = "private-ssh.example"),
            subscriptions = listOf(SubscriptionSource("source", "https://example.test/SUBSCRIPTION_SECRET",
                lastRefreshStatus = "PRIVATE_REFRESH_EXCEPTION")),
            statusMessage = "PRIVATE_EXCEPTION")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(persisted, listOf(DesktopLocationRecord(0, "", raw, "Public", "127.0.0.1",
                "PRIVATE_PARSE_EXCEPTION", "PRIVATE_BENCHMARK_EXCEPTION", true, true))))
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val client = DesktopRemoteControlSession.connect(scope, {
            withContext(Dispatchers.IO) { DesktopActivationServer.requestCliCommand(it, endpoint) }
        }, 60_000).getOrThrow()
        try {
            val before = client.presentation().getOrThrow()
            assertEquals(owner.controllerId, before.controllerId)
            assertEquals(service.configurationRevision, before.configurationRevision)
            val frontend = before.frontend
            assertFalse(frontend.runtime.runtimeRunning)
            assertEquals("Public", frontend.locations.single().name)
            assertEquals(0L, frontend.statistics.successfulStarts)
            assertNull(frontend.subscriptions.single().refreshStatus)
            assertTrue(frontend.subscriptions.single().refreshStatusUnavailable)
            for (section in listOf("settings", "runtime", "source", "routing", "activity", "statistics", "update")) {
                val original = (before.values.getValue(section) as ControlValue.ObjectValue).values
                for (key in original.keys) {
                    val malformed = before.copy(values = before.values + (section to ControlValue.ObjectValue(original - key)))
                    assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL,
                        assertFailsWith<com.kardinal.vpncontrol.control.ControlProtocolException> { malformed.frontend }.code,
                        "$section.$key must be required")
                }
                val extra = before.copy(values = before.values + (section to ControlValue.ObjectValue(original +
                    ("privateKey" to ControlValue.Text("SECRET")))))
                assertFailsWith<com.kardinal.vpncontrol.control.ControlProtocolException> { extra.frontend }
            }
            val serialized = ControlProtocolCodec.encodeValues(before.values)
            for (secret in listOf("PROFILE_PASSWORD", "SUBSCRIPTION_SECRET", "private-dns.example", "private-ssh.example", "PRIVATE_EXCEPTION",
                "PRIVATE_PARSE_EXCEPTION", "PRIVATE_BENCHMARK_EXCEPTION", "PRIVATE_REFRESH_EXCEPTION"))
                assertFalse(serialized.contains(secret), "Presentation exposed $secret")
            assertTrue(serialized.contains("Public"))
            val location = ((before.values.getValue("locations") as ControlValue.ArrayValue).values.single() as ControlValue.ObjectValue).values
            assertEquals(ControlValue.Text(service.controlLocationId(service.visibleDesktopLocations().single())!!), location["id"])
            assertFalse(location.containsKey("rawLink"))
            val rendered = before.locations.single().toSharedRow()
            assertEquals("", rendered.rawLink)
            assertTrue(requireNotNull(rendered.selection).selected)
            assertFalse(requireNotNull(rendered.selection).active)
            service.toggleDnsDialog()
            service.setCustomDnsDraft("https://UNSAVED_PRIVATE.example/dns-query")
            val afterDraft = client.presentation().getOrThrow()
            assertEquals(before.configurationRevision, afterDraft.configurationRevision)
            assertFalse(ControlProtocolCodec.encodeValues(afterDraft.values).contains("UNSAVED_PRIVATE"))
            service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(7))).getOrThrow()
            val committed = client.presentation().getOrThrow()
            assertEquals(before.configurationRevision + 1, committed.configurationRevision)
            assertEquals(ControlValue.IntegerValue(7), (committed.values.getValue("settings") as ControlValue.ObjectValue).values["validation.batch-size"])
            assertTrue(owner.session.operationSnapshot().isEmpty())
            assertEquals("CONFLICT", owner.session.execute(DesktopCliCommand.ControlPresentationRead("read", "other-owner")).message)
        } finally { client.close(); scope.cancel(); server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
