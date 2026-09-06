package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopRoutingCliEndToEndTest {
    @Test
    fun routingRoundTripsThroughClientFilesAndSharedGuiRules() {
        val directory = Files.createTempDirectory("vpn-control-routing-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), empty)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { service.executeCliCommand(it) } }, portFile = endpoint,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            assertEquals(0, invoke("routing", "set", "direct-domains", "*.Example.COM.\n.local").first)
            assertEquals(listOf("example.com", "local"), service.state.routingRules.directDomainSuffixes)
            service.setRoutingIgnoreRulesDraft(true)
            assertTrue(RoutingRulesTransfer.import(invoke("routing", "show").second).ignoreRules)
            val original = service.state.routingRules
            assertEquals(1, invoke("routing", "set", "ignore-rules", "not-boolean").first)
            assertEquals(original, service.state.routingRules)
            val output = directory.resolve("routing export 東京.json")
            assertEquals(0, invoke("routing", "export", "--output", output.toString()).first)
            assertEquals(original, RoutingRulesTransfer.import(Files.readString(output)))
            assertEquals(1, invoke("routing", "export", "--output", output.toString()).first)
            assertEquals(original, RoutingRulesTransfer.import(Files.readString(output)))
            assertEquals(0, invoke("routing", "set", "direct-domains", "replacement.example").first)
            assertEquals(0, invoke("routing", "import", "--input", output.toString()).first)
            assertEquals(original, service.state.routingRules)
            assertEquals(original, DesktopStateStore(directory).loadWorkspace(empty).persistedState.routingRules)
            assertEquals(1, DesktopCli.handleArgs(arrayOf("routing", "apps", "clear"), printLine = {},
                requestCommand = { error("Unsupported app assignment must not contact owner") }))
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }
}
