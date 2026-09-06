package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopDiagnosticsCliTest {
    @Test
    fun logsAndReportsRedactStructuredSecretsAndStatsUseRealCounters() {
        val directory = Files.createTempDirectory("vpn-control-diagnostics-cli")
        val secretStatus = SettingsStatusMessages.homeSshPrivateKeyImportFailed("https://example.test/private/SECRET-TOKEN")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(successfulStarts = 3, successfulStops = 2,
                statusMessage = secretStatus,
                connectionLog = listOf(ConnectionLogEntry("id", secretStatus, 100))), emptyList()))
        val endpoint = directory.resolve("activation.port")
        val owner = DesktopControllerOwner(service)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            val stats = invoke("stats")
            assertEquals(0, stats.first)
            assertTrue(stats.second.contains("\"successfulStarts\":3"))
            assertTrue(stats.second.contains("\"elapsedMillis\":null"))
            assertFalse(stats.second.contains("rxBytes"))
            val logs = invoke("logs", "--limit", "1")
            assertEquals(0, logs.first)
            assertFalse(logs.second.contains("SECRET-TOKEN"))
            assertEquals("", invoke("logs", "--limit", "0").second)
            fun json(vararg args: String): com.kardinal.vpncontrol.model.ControlResult {
                val result = invoke("--json", *args)
                assertEquals(0, result.first, result.second)
                return com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(result.second).also {
                    assertEquals(owner.controllerId, it.controllerId)
                    assertTrue(it.final)
                }
            }
            val jsonStats = json("stats")
            assertEquals(com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeValues(stats.second), jsonStats.data)
            val jsonLogs = json("logs", "--limit", "1")
            assertFalse(jsonLogs.toString().contains("SECRET-TOKEN"))
            assertEquals(1, (jsonLogs.data.getValue("entries") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(0, (json("logs", "--limit", "0").data.getValue("entries") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(1, invoke("--json", "logs", "--limit", "-1").first)
            val followed = mutableListOf<String>()
            var following = true
            assertEquals(130, DesktopCli.handleArgs(arrayOf("--json", "logs", "--follow"), printLine = followed::add,
                requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                streamPause = { following = false }, streamActive = { following }))
            assertFalse(followed.joinToString("\n").contains("SECRET-TOKEN"))
            assertEquals(2, followed.size)
            assertTrue(json("source", "show").data.containsKey("mode"))
            assertEquals(com.kardinal.vpncontrol.model.AppLanguage.entries.size,
                (json("settings", "languages").data.getValue("languages") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(jsonStats.configurationRevision, jsonLogs.configurationRevision)
            assertTrue(owner.session.operationSnapshot().isEmpty())
            val output = directory.resolve("diagnostic report.txt")
            val before = service.state
            assertEquals(0, invoke("diagnostics", "export", "--output", output.toString()).first)
            val report = Files.readString(output)
            assertTrue(report.contains("VPN Control Desktop Diagnostics"))
            assertFalse(report.contains("SECRET-TOKEN"))
            assertEquals(before, service.state)
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
