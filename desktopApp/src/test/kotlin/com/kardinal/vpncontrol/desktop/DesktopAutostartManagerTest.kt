package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopAutostartManagerTest {
    @Test
    fun setEnabledCreatesAndRemovesXdgAutostartEntryWithoutSystemdService() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val commands = mutableListOf<List<String>>()
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                commandRunner = { command ->
                    commands += command
                    DesktopAutostartCommandResult(0, "")
                },
                systemctlResolver = { tempDir.resolve("systemctl") },
                executableChecker = launcherExecutableChecker(launcher),
                environment = { emptyMap() },
            )

            assertFalse(manager.isEnabled())

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())

            val content = Files.readString(tempDir.resolve("autostart").resolve("vpn-control.desktop"))
            assertTrue(content.contains("Type=Application"))
            assertTrue(content.contains("Name=VPN Control"))
            assertTrue(content.contains("Exec=${desktopExecCommand(launcher)} --autostart"))
            assertTrue(content.contains("X-GNOME-Autostart-enabled=true"))
            assertFalse(Files.exists(tempDir.resolve("systemd").resolve("user").resolve("vpn-control.service")))
            assertFalse(
                Files.exists(
                    tempDir.resolve("systemd")
                        .resolve("user")
                        .resolve("default.target.wants")
                        .resolve("vpn-control.service"),
                ),
            )

            val disabled = manager.setEnabled(false)

            assertTrue(disabled.isSuccess)
            assertFalse(manager.isEnabled())
            assertFalse(Files.exists(tempDir.resolve("autostart").resolve("vpn-control.desktop")))
            assertFalse(Files.exists(tempDir.resolve("systemd").resolve("user").resolve("vpn-control.service")))
            assertFalse(commands.any { it.takeLast(2) == listOf("--user", "daemon-reload") })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledRemovesLegacyLinuxSystemdAutostartWithoutStoppingRuntime() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-legacy")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val systemdUserDir = tempDir.resolve("systemd").resolve("user")
            val wantsDir = systemdUserDir.resolve("default.target.wants")
            Files.createDirectories(wantsDir)
            Files.writeString(
                systemdUserDir.resolve("vpn-control.service"),
                """
                    |[Unit]
                    |Description=VPN Control Desktop
                    |
                    |[Service]
                    |ExecStart=/opt/vpn-control/bin/vpn-control --autostart
                    |
                """.trimMargin(),
            )
            Files.writeString(wantsDir.resolve("vpn-control.service"), "legacy copied service")
            val commands = mutableListOf<List<String>>()
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                commandRunner = { command ->
                    commands += command
                    DesktopAutostartCommandResult(0, "")
                },
                systemctlResolver = { tempDir.resolve("systemctl") },
                executableChecker = launcherExecutableChecker(launcher),
                environment = { emptyMap() },
            )

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())
            assertTrue(Files.exists(tempDir.resolve("autostart").resolve("vpn-control.desktop")))
            assertFalse(Files.exists(systemdUserDir.resolve("vpn-control.service")))
            assertFalse(Files.exists(wantsDir.resolve("vpn-control.service")))
            assertTrue(commands.any { it.takeLast(3) == listOf("--user", "disable", "vpn-control.service") })
            assertTrue(commands.any { it.takeLast(2) == listOf("--user", "daemon-reload") })
            assertFalse(commands.flatten().any { it == "--now" })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun isEnabledMigratesLegacyLinuxSystemdAutostartToXdgEntry() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-migrate")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val systemdUserDir = tempDir.resolve("systemd").resolve("user")
            Files.createDirectories(systemdUserDir)
            Files.writeString(
                systemdUserDir.resolve("vpn-control.service"),
                """
                    |[Unit]
                    |Description=VPN Control Desktop
                    |
                    |[Service]
                    |ExecStart=/opt/vpn-control/bin/vpn-control --autostart
                    |
                """.trimMargin(),
            )
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                commandRunner = { DesktopAutostartCommandResult(0, "") },
                systemctlResolver = { tempDir.resolve("systemctl") },
                executableChecker = launcherExecutableChecker(launcher),
                environment = { emptyMap() },
            )

            assertTrue(manager.isEnabled())
            assertTrue(Files.exists(tempDir.resolve("autostart").resolve("vpn-control.desktop")))
            assertFalse(Files.exists(systemdUserDir.resolve("vpn-control.service")))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun disabledHiddenEntryIsReportedAsDisabled() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-hidden")
        try {
            val launcher = createExecutableLauncher(tempDir)
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
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                environment = { emptyMap() },
            )

            assertFalse(manager.isEnabled())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun staleXdgEntryWithMissingExecutableIsDisabledAndRewrittenWhenEnabled() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-stale")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val autostartDir = tempDir.resolve("autostart")
            Files.createDirectories(autostartDir)
            Files.writeString(
                autostartDir.resolve("vpn-control.desktop"),
                """
                    |[Desktop Entry]
                    |Type=Application
                    |Name=VPN Control
                    |Exec="/missing/vpn-control" --autostart
                    |
                """.trimMargin(),
            )

            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { emptyMap() },
            )

            assertFalse(manager.isEnabled())

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())
            val content = Files.readString(autostartDir.resolve("vpn-control.desktop"))
            assertTrue(content.contains("Exec=${desktopExecCommand(launcher)} --autostart"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledAddsI3FallbackWhenRunningInI3Session() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-i3")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val i3Config = tempDir.resolve("i3").resolve("config")
            Files.createDirectories(i3Config.parent)
            Files.writeString(
                i3Config,
                """
                    |# i3 config
                    |exec --no-startup-id nm-applet
                    |
                """.trimMargin(),
            )
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { mapOf("XDG_CURRENT_DESKTOP" to "i3") },
            )

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())
            val content = Files.readString(i3Config)
            assertTrue(content.contains("# VPN Control autostart: begin"))
            assertTrue(content.contains(i3AutostartExecLine(launcher)))
            assertTrue(content.contains("exec --no-startup-id nm-applet"))

            val enabledAgain = manager.setEnabled(true)

            assertTrue(enabledAgain.isSuccess)
            val rewrittenContent = Files.readString(i3Config)
            assertEquals(1, countOccurrences(rewrittenContent, "# VPN Control autostart: begin"))
            assertEquals(1, countOccurrences(rewrittenContent, "# VPN Control autostart: end"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledAddsI3FallbackForLauncherPathWithShellSpecialCharacters() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-i3-spaces")
        try {
            val launcher = createExecutableLauncher(tempDir, "launcher dir/owner's vpn-control")
            val i3Config = tempDir.resolve("i3").resolve("config")
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { mapOf("XDG_CURRENT_DESKTOP" to "i3") },
            )

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())
            val content = Files.readString(i3Config)
            assertTrue(content.contains(i3AutostartExecLine(launcher)))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledKeepsI3ConfigUntouchedOutsideI3Session() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-no-i3")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { emptyMap() },
            )

            val enabled = manager.setEnabled(true)

            assertTrue(enabled.isSuccess)
            assertTrue(manager.isEnabled())
            assertFalse(Files.exists(tempDir.resolve("i3").resolve("config")))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun isEnabledRepairsI3FallbackWhenXdgEntryIsEnabledInI3Session() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-i3-repair")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val autostartDir = tempDir.resolve("autostart")
            Files.createDirectories(autostartDir)
            Files.writeString(
                autostartDir.resolve("vpn-control.desktop"),
                """
                    |[Desktop Entry]
                    |Type=Application
                    |Name=VPN Control
                    |Exec=${desktopExecCommand(launcher)} --autostart
                    |
                """.trimMargin(),
            )
            val i3Config = tempDir.resolve("i3").resolve("config")
            Files.createDirectories(i3Config.parent)
            Files.writeString(
                i3Config,
                """
                    |# VPN Control autostart: begin
                    |exec --no-startup-id ${desktopExecCommand(launcher)} --autostart
                    |# VPN Control autostart: end
                    |
                """.trimMargin(),
            )
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { mapOf("DESKTOP_SESSION" to "i3") },
            )

            assertTrue(manager.isEnabled())
            val content = Files.readString(i3Config)
            assertTrue(content.contains("# VPN Control autostart: begin"))
            assertTrue(content.contains(i3AutostartExecLine(launcher)))
            assertFalse(content.contains("exec --no-startup-id ${desktopExecCommand(launcher)} --autostart"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledFalseRemovesOnlyManagedI3Fallback() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-i3-disable")
        try {
            val launcher = createExecutableLauncher(tempDir)
            val i3Config = tempDir.resolve("i3").resolve("config")
            Files.createDirectories(i3Config.parent)
            Files.writeString(
                i3Config,
                """
                    |# before
                    |# VPN Control autostart: begin
                    |exec --no-startup-id ${desktopExecCommand(launcher)} --autostart
                    |# VPN Control autostart: end
                    |# after
                    |
                """.trimMargin(),
            )
            val autostartDir = tempDir.resolve("autostart")
            Files.createDirectories(autostartDir)
            Files.writeString(
                autostartDir.resolve("vpn-control.desktop"),
                """
                    |[Desktop Entry]
                    |Type=Application
                    |Name=VPN Control
                    |Exec=${desktopExecCommand(launcher)} --autostart
                    |
                """.trimMargin(),
            )
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { mapOf("I3SOCK" to "/run/user/1000/i3/ipc.sock") },
            )

            val disabled = manager.setEnabled(false)

            assertTrue(disabled.isSuccess)
            assertFalse(manager.isEnabled())
            assertFalse(Files.exists(autostartDir.resolve("vpn-control.desktop")))
            val content = Files.readString(i3Config)
            assertTrue(content.contains("# before"))
            assertTrue(content.contains("# after"))
            assertFalse(content.contains("# VPN Control autostart: begin"))
            assertFalse(content.contains("--autostart"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun setEnabledWritesAndDeletesWindowsHighestPrivilegeScheduledTask() {
        val commands = mutableListOf<List<String>>()
        var taskEnabled = false
        var legacyRunEnabled = false
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.take(2) == listOf("schtasks", "/Query") -> {
                        DesktopAutostartCommandResult(if (taskEnabled) 0 else 1, "")
                    }
                    command.take(2) == listOf("schtasks", "/Create") -> {
                        taskEnabled = true
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    command.take(2) == listOf("schtasks", "/Delete") -> {
                        taskEnabled = false
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    command.take(2) == listOf("reg", "query") -> {
                        DesktopAutostartCommandResult(if (legacyRunEnabled) 0 else 1, "")
                    }
                    command.take(2) == listOf("reg", "delete") -> {
                        legacyRunEnabled = false
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
                "schtasks",
                "/Create",
                "/TN",
                "VPN Control",
                "/SC",
                "ONLOGON",
                "/TR",
                "\"C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe\" --autostart",
                "/RL",
                "HIGHEST",
                "/F",
            )
        })

        val disableResult = manager.setEnabled(false)

        assertTrue(disableResult.isSuccess)
        assertFalse(manager.isEnabled())
        assertTrue(commands.any { command ->
            command == listOf(
                "schtasks",
                "/Delete",
                "/TN",
                "VPN Control",
                "/F",
            )
        })
    }

    @Test
    fun isEnabledMigratesLegacyWindowsRunEntryToHighestPrivilegeScheduledTask() {
        val commands = mutableListOf<List<String>>()
        var taskEnabled = false
        var legacyRunEnabled = true
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.take(2) == listOf("schtasks", "/Query") -> {
                        DesktopAutostartCommandResult(if (taskEnabled) 0 else 1, "")
                    }
                    command.take(2) == listOf("schtasks", "/Create") -> {
                        taskEnabled = true
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    command.take(2) == listOf("reg", "query") -> {
                        DesktopAutostartCommandResult(if (legacyRunEnabled) 0 else 1, "")
                    }
                    command.take(2) == listOf("reg", "delete") -> {
                        legacyRunEnabled = false
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    else -> DesktopAutostartCommandResult(1, "unexpected command")
                }
            },
        )

        assertTrue(manager.isEnabled())
        assertTrue(taskEnabled)
        assertFalse(legacyRunEnabled)
        assertTrue(commands.any { it.take(2) == listOf("schtasks", "/Create") })
        assertTrue(commands.any { it.take(2) == listOf("reg", "delete") })
    }

    private fun createExecutableLauncher(tempDir: Path): String {
        return createExecutableLauncher(tempDir, "vpn-control")
    }

    private fun createExecutableLauncher(tempDir: Path, relativePath: String): String {
        val launcher = tempDir.resolve(relativePath)
        Files.createDirectories(launcher.parent)
        Files.writeString(launcher, "#!/usr/bin/env sh\nexit 0\n")
        assertTrue(launcher.toFile().setExecutable(true))
        return launcher.toString()
    }

    private fun launcherExecutableChecker(launcher: String): (Path) -> Boolean {
        return { path -> path.toString() == launcher && Files.exists(path) }
    }

    private fun desktopExecCommand(value: String): String {
        val escaped = buildString {
            value.forEach { char ->
                when (char) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '$' -> append("\\$")
                    '`' -> append("\\`")
                    else -> append(char)
                }
            }
        }
        return "\"$escaped\""
    }

    private fun i3AutostartExecLine(value: String): String {
        return "exec --no-startup-id sh -c 'exec \"\$1\" --autostart' vpn-control-i3 ${shellArg(value)}"
    }

    private fun shellArg(value: String): String {
        return "'${value.replace("'", "'\"'\"'")}'"
    }

    private fun countOccurrences(value: String, needle: String): Int {
        return Regex.escape(needle).toRegex().findAll(value).count()
    }
}
