package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopSettingsCliEndToEndTest {
    @Test
    fun terminalSettingsAreAtomicDurableAndVisibleToGui() {
        val directory = Files.createTempDirectory("vpn-control-settings-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val store = DesktopStateStore(directory)
        val service = DesktopAppServiceFactory.createForTesting(store = store, initialWorkspace = empty)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { service.executeCliCommand(it) } }, portFile = endpoint,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                val result = DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Must reuse existing owner") })
                return result to lines.joinToString("\n")
            }
            val input = directory.resolve("DNS settings 東京.json")
            Files.writeString(input, """{"dns.endpoint":"https://dns.example","dns.mode":"custom-doh","mode":"proxy-only"}""")
            assertEquals(0, invoke("settings", "apply", "--input", input.toString()).first)
            assertEquals(DnsMode.CUSTOM_DOH, service.state.dnsSettings.mode)
            assertEquals("https://dns.example/dns-query", service.state.dnsSettings.endpoint)
            assertEquals(AppMode.PROXY_ONLY, service.state.appMode)
            assertTrue(invoke("settings", "show", "dns.endpoint").second.contains("https://dns.example/dns-query"))
            val before = service.state
            Files.writeString(input, """{"dns.endpoint":"http://invalid.example","language":"en"}""")
            assertEquals(1, invoke("settings", "apply", "--input", input.toString()).first)
            assertEquals(before, service.state)
            assertEquals(0, invoke("settings", "set", "validation.batch-size", "4").first)
            assertEquals(4, service.state.validationSettings.batchSize)
            assertEquals(1, invoke("settings", "set", "ssh.enabled", "not-a-boolean").first)
            runBlocking { service.setAppMode(AppMode.PROXY_ONLY) }
            assertEquals(0, invoke("settings", "show", "mode").first)
            val reloaded = DesktopStateStore(directory).loadWorkspace(empty)
            assertEquals(service.state.dnsSettings, reloaded.persistedState.dnsSettings)
            assertEquals(4, reloaded.persistedState.validationSettings.batchSize)
            assertEquals(AppMode.PROXY_ONLY, reloaded.persistedState.appMode)
            assertFalse(service.state.isVpnRunning)
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally {
            server.close()
            directory.toFile().deleteRecursively()
        }
    }
}
