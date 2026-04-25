package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopAutostartManagerTest {
    @Test
    fun setEnabledCreatesAndRemovesXdgAutostartEntry() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart")
        try {
            val commands = mutableListOf<List<String>>()
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { "/opt/vpn-control/bin/vpn-control" },
                platform = DesktopAutostartPlatform.LINUX,
                commandRunner = { command ->
                    commands += command
                    DesktopAutostartCommandResult(0, "")
                },
                systemctlResolver = { tempDir.resolve("systemctl") },
            )

            assertFalse(manager.isEnabled())

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())

            val content = Files.readString(tempDir.resolve("autostart").resolve("vpn-control.desktop"))
            assertTrue(content.contains("Type=Application"))
            assertTrue(content.contains("Name=VPN Control"))
            assertTrue(content.contains("Exec=\"/opt/vpn-control/bin/vpn-control\" --autostart"))
            assertTrue(content.contains("X-GNOME-Autostart-enabled=true"))
            val service = Files.readString(tempDir.resolve("systemd").resolve("user").resolve("vpn-control.service"))
            assertTrue(service.contains("ExecStart=/opt/vpn-control/bin/vpn-control --autostart"))
            assertTrue(Files.exists(tempDir.resolve("systemd").resolve("user").resolve("default.target.wants").resolve("vpn-control.service")))

            val disabled = manager.setEnabled(false)

            assertTrue(disabled.isSuccess)
            assertFalse(manager.isEnabled())
            assertFalse(Files.exists(tempDir.resolve("autostart").resolve("vpn-control.desktop")))
            assertFalse(Files.exists(tempDir.resolve("systemd").resolve("user").resolve("vpn-control.service")))
            assertTrue(commands.any { it.takeLast(2) == listOf("--user", "daemon-reload") })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun disabledHiddenEntryIsReportedAsDisabled() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-hidden")
        try {
            val autostartDir = tempDir.resolve("autostart")
            Files.createDirectories(autostartDir)
            Files.writeString(
                autostartDir.resolve("vpn-control.desktop"),
                """
                    |[Desktop Entry]
                    |Type=Application
                    |Name=VPN Control
                    |Hidden=true
                    |
                """.trimMargin(),
            )

            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { "/opt/vpn-control/bin/vpn-control" },
                platform = DesktopAutostartPlatform.LINUX,
            )

            assertFalse(manager.isEnabled())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledWritesAndDeletesWindowsRunRegistryEntry() {
        val commands = mutableListOf<List<String>>()
        var enabled = false
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.take(2) == listOf("reg", "query") -> {
                        DesktopAutostartCommandResult(if (enabled) 0 else 1, "")
                    }
                    command.take(2) == listOf("reg", "add") -> {
                        enabled = true
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    command.take(2) == listOf("reg", "delete") -> {
                        enabled = false
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    else -> DesktopAutostartCommandResult(1, "unexpected command")
                }
            },
        )

        assertFalse(manager.isEnabled())

        val enableResult = manager.setEnabled(true)

        assertTrue(enableResult.isSuccess)
        assertTrue(manager.isEnabled())
        assertTrue(commands.any { command ->
            command == listOf(
                "reg",
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                "VPN Control",
                "/t",
                "REG_SZ",
                "/d",
                "\"C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe\"",
                "/f",
            )
        })

        val disableResult = manager.setEnabled(false)

        assertTrue(disableResult.isSuccess)
        assertFalse(manager.isEnabled())
        assertTrue(commands.any { command ->
            command == listOf(
                "reg",
                "delete",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "/v",
                "VPN Control",
                "/f",
            )
        })
    }
}
