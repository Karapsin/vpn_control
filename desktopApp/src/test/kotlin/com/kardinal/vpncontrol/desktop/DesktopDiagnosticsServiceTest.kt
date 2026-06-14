package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DiagnosticsStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopDiagnosticsServiceTest {
    @Test
    fun exportWritesDiagnosticsAndUpdatesStatus() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-diagnostics-service")
        try {
            val store = DesktopStateStore(tempDir)
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = tempDir.resolve("runtime"),
                singBoxResolver = DesktopSingBoxResolver(
                    toolsDir = tempDir.resolve("tools"),
                    classLoader = javaClass.classLoader,
                ),
            )
            store.writeRuntimeConfig(secretRuntimeConfig())
            Files.createDirectories(tempDir.resolve("runtime"))
            Files.writeString(
                tempDir.resolve("runtime").resolve("runtime-sing-box.log"),
                "outbound/vless[proxy]: outbound connection to 203.0.113.10:443 user: tester /home/tester/.vpn-control-desktop",
            )
            var state = MainUiState(
                statusMessage = "Ready",
                selectedProfileServer = "secret.example.com",
                selectedProfileSourceUrl = "https://example.com/subscription/secret-token",
                selectedProfileRawLink = secretProfileLink(),
                subscriptions = listOf(
                    SubscriptionSource(
                        id = "sub-1",
                        url = "https://example.com/subscription/secret-token",
                        customName = "Primary",
                    ),
                ),
            )
            val service = DesktopDiagnosticsService(
                stateProvider = { state },
                desktopStore = store,
                runtimeManager = runtimeManager,
                updateState = { transform -> state = transform(state) },
            )
            val target = tempDir.resolve("diagnostics.txt")

            service.export(Result.success(target))

            val report = Files.readString(target)
            assertTrue(report.contains("VPN Control Desktop Diagnostics"))
            assertTrue(report.contains("status=Ready"))
            assertTrue(report.contains("selected_profile_server_present=true"))
            assertTrue(report.contains("selected_profile_source_url=https://example.com/<redacted>"))
            assertTrue(report.contains("[runtime_config_summary]"))
            assertTrue(report.contains("proxy_outbound_type=vless"))
            assertTrue(report.contains("proxy_server_present=true"))
            assertTrue(report.contains("url=https://example.com/<redacted>"))
            assertFalse(report.contains("secret-token"))
            assertFalse(report.contains("secret.example.com"))
            assertFalse(report.contains("11111111-1111-4111-8111-111111111111"))
            assertFalse(report.contains("public-secret"))
            assertFalse(report.contains("203.0.113.10"))
            assertFalse(report.contains("tester"))
            assertEquals(DiagnosticsStatusMessages.diagnosticsExportedTo(target.toString()), state.statusMessage)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun exportCancellationUpdatesStatusWithoutWritingFile() = runTest {
        var state = MainUiState()
        val tempDir = Files.createTempDirectory("vpn-control-diagnostics-cancel")
        try {
            val store = DesktopStateStore(tempDir)
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = tempDir.resolve("runtime"),
                singBoxResolver = DesktopSingBoxResolver(
                    toolsDir = tempDir.resolve("tools"),
                    classLoader = javaClass.classLoader,
                ),
            )
            val service = DesktopDiagnosticsService(
                stateProvider = { state },
                desktopStore = store,
                runtimeManager = runtimeManager,
                updateState = { transform -> state = transform(state) },
            )

            service.export(Result.success(null))

            assertEquals(DiagnosticsStatusMessages.diagnosticsExportCanceled(), state.statusMessage)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}

private fun secretProfileLink(): String =
    "vless://11111111-1111-4111-8111-111111111111@secret.example.com:8443" +
        "?type=tcp&security=reality&sni=secret-sni.example.com&pbk=public-secret&sid=short-secret#Secret"

private fun secretRuntimeConfig(): String = """
    {
      "inbounds": [{"type": "tun", "tag": "tun-in"}],
      "outbounds": [
        {
          "type": "vless",
          "tag": "proxy",
          "server": "secret.example.com",
          "server_port": 8443,
          "uuid": "11111111-1111-4111-8111-111111111111",
          "tls": {
            "server_name": "secret-sni.example.com",
            "reality": {"public_key": "public-secret", "short_id": "short-secret"}
          }
        }
      ],
      "route": {"rules": [{"action": "sniff"}]},
      "dns": {"servers": [{"tag": "remote-dns", "server": "1.1.1.1"}]}
    }
""".trimIndent()
