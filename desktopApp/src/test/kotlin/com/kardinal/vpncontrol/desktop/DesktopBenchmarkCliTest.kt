package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ProfileBenchmark
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopBenchmarkCliTest {
    @Test
    fun guiReferenceBenchmarksIntendedNumericNamedRowAndRejectsStaleConfiguration() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-gui-benchmark-reference")
        val probed = mutableListOf<String>()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            locationBenchmarker = { profile, _, _, _ ->
                probed += profile.server
                Result.success(ProfileBenchmark(profile = profile, primaryStatus = "ok", secondaryStatus = "ok",
                    primaryTotal = 1.0, secondaryTotal = null, score = 1.0, detail = "tcp=1ms test=ok"))
            })
        try {
            service.setSourceMode(com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.saveLocation("socks://127.0.0.1:1080#2").getOrThrow()
            val intended = service.saveLocation("socks://127.0.0.2:1080#Target").getOrThrow()
            val command = assertNotNull(desktopGuiBenchmarkCommand(intended.index, service.visibleDesktopLocations(), service::controlLocationId))
            assertEquals(0, service.executeCliCommand(command).exitCode)
            assertEquals(listOf("127.0.0.2"), probed)
            // Terminal exact names retain precedence over their numeric position.
            assertEquals(0, service.executeCliCommand(DesktopCliCommand.LocationBenchmark("2")).exitCode)
            assertEquals(listOf("127.0.0.2", "127.0.0.1"), probed)
            service.saveLocation("socks://127.0.0.3:1080#Target", intended.index, intended.rawLink).getOrThrow()
            val rejected = service.executeCliCommand(command)
            assertEquals(1, rejected.exitCode)
            assertEquals("CONFLICT", rejected.message)
            assertEquals(2, probed.size)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test
    fun authenticatedBenchmarkUsesVisibleSelectorAndPersistsWithoutSelecting() {
        val directory = Files.createTempDirectory("vpn-control-benchmark-cli")
        val store = DesktopStateStore(directory)
        var probeCount = 0
        var pass = true
        val service = DesktopAppServiceFactory.createForTesting(store,
            locationBenchmarker = { profile, _, _, _ ->
                probeCount++
                Result.success(ProfileBenchmark(profile = profile, primaryStatus = "ok",
                    secondaryStatus = if (pass) "ok" else "timeout", primaryTotal = 12.0,
                    secondaryTotal = null, score = 12.0,
                    detail = "tcp=12.0ms test=${if (pass) "ok" else "timeout"}"))
            })
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
            val input = directory.resolve("配置 input.txt")
            assertEquals(0, invoke("source", "set", "current-locations").first)
            Files.writeString(input, "socks://127.0.0.1:1080#Benchmark")
            val added = invoke("locations", "add", "--input", input.toString())
            assertEquals(0, added.first, added.second)
            val selected = service.state.selectedProfileRawLink
            assertEquals(1, invoke("locations", "benchmark", "99").first)
            assertEquals(0, probeCount)
            assertEquals(0, invoke("locations", "benchmark", "1").first)
            assertEquals(1, probeCount)
            assertTrue(service.desktopLocations.single().isValid)
            pass = false
            assertEquals(1, invoke("locations", "benchmark", "Benchmark").first)
            assertEquals(2, probeCount)
            assertFalse(service.desktopLocations.single().isValid)
            assertEquals(selected, service.state.selectedProfileRawLink)
            assertFalse(service.state.isVpnRunning)
            assertFalse(service.state.isBusy)
            val restored = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
            assertFalse(restored.locations.single().isValid)
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }
}
