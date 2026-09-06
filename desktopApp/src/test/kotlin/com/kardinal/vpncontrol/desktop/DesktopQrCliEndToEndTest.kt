package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopQrCliEndToEndTest {
    @Test fun authenticatedQrImportsAndExportsPreserveDurableLocationAndRoutingMeaning() {
        val directory = Files.createTempDirectory("qr-transport-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), empty)
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, portFile = endpoint,
            controllerId = owner.controllerId))
        try {
            fun invoke(vararg args: String): Int? = DesktopCli.handleArgs(arrayOf(*args), printLine = {},
                requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                startHeadlessController = { error("Reuse authenticated test owner") })
            val input = directory.resolve("東京 input.png")
            Files.write(input, DesktopQrImage.encode("socks://127.0.0.1:1080#Office").getOrThrow())
            assertEquals(0, invoke("source", "set", "current-locations"))
            assertEquals(0, invoke("--json", "locations", "add", "--qr-image", input.toString()))
            val location = service.state.currentLocations.single()
            // Bulk import is still a locations document, not a silent alias for single add.
            assertEquals(1, invoke("--json", "locations", "import", "--qr-image", input.toString()))
            assertEquals(listOf(location), service.state.currentLocations)
            val locations = directory.resolve("locations export.png")
            assertEquals(0, invoke("locations", "export", "--format", "qr-png", "--output", locations.toString()))
            assertEquals(0, invoke("locations", "delete", "Office"))
            assertEquals(0, invoke("--json", "locations", "import", "--qr-image", locations.toString()))
            assertEquals(listOf(location), service.state.currentLocations)

            assertEquals(0, invoke("routing", "set", "direct-domains", "example.com"))
            val originalRules = service.state.routingRules
            val routing = directory.resolve("routing export.png")
            assertEquals(0, invoke("routing", "export", "--format", "qr-png", "--output", routing.toString()))
            assertEquals(0, invoke("routing", "set", "direct-domains", "replacement.example"))
            assertEquals(0, invoke("--json", "routing", "import", "--qr-image", routing.toString()))
            assertEquals(originalRules, service.state.routingRules)
            val source = "https://example.invalid/subscription"
            Files.write(input, DesktopQrImage.encode(source).getOrThrow())
            assertEquals(0, invoke("--json", "subscriptions", "add", "--qr-image", input.toString(), "--name", "QR source"))
            assertEquals(source, service.state.subscriptions.single().url)
            val durable = DesktopStateStore(directory).loadWorkspace(empty)
            assertEquals(originalRules, durable.persistedState.routingRules)
            assertEquals(1, durable.locations.size)
            assertEquals(source, durable.persistedState.subscriptions.single().url)
            assertTrue(durable.locations.single().rawLink.contains("127.0.0.1"))
            assertFalse(service.state.isVpnRunning)
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally {
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
