package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopAutostartManagerTest {
    @Test
    fun linuxAutostartPreservesWorkspaceAndEscapesDesktopFieldCodes() {
        val tempDir = Files.createTempDirectory("vpn-control-autostart-workspace")
        try {
            val launcher = createExecutableLauncher(tempDir, "launcher %f dir/vpn-control")
            val workspace = tempDir.resolve("owner's 東京 %f \$USER & workspace")
            val manager = DesktopAutostartManager(
                configHome = tempDir,
                commandResolver = { launcher },
                platform = DesktopAutostartPlatform.LINUX,
                workspaceDirectory = workspace,
                executableChecker = launcherExecutableChecker(launcher),
                environment = { mapOf("I3SOCK" to "test-owned-session") },
            )
            assertTrue(manager.setEnabled(true).isSuccess)
            assertTrue(manager.inspectEnabled())
            val entry = Files.readString(tempDir.resolve("autostart/vpn-control.desktop"))
            assertTrue(entry.contains("launcher %%f dir"))
            assertTrue(entry.contains(" --autostart --state-dir \""))
            assertTrue(entry.contains("owner's 東京 %%f \\\\\$USER & workspace"))
            assertFalse(Files.exists(workspace))

            // Verify i3 recognition independently of the XDG entry.
            Files.delete(tempDir.resolve("autostart/vpn-control.desktop"))
            assertTrue(manager.inspectEnabled())
            val line = Files.readAllLines(tempDir.resolve("i3/config")).single { it.startsWith("exec ") }
            assertTrue(line.endsWith(shellArg(workspace.toString())))
            if (Files.isExecutable(Path.of("/bin/sh"))) {
                // Only this disposable argument-echo launcher is executed, never the application.
                Files.writeString(Path.of(launcher), "#!/bin/sh\nprintf '%s\\n' \"\$@\"\n")
                val process = ProcessBuilder("/bin/sh", "-c", line.removePrefix("exec --no-startup-id ")).start()
                assertTrue(process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(0, process.exitValue())
                assertEquals(listOf("--autostart", "--state-dir", workspace.toString()),
                    process.inputStream.bufferedReader().readLines())
            }
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windowsAutostartPreservesExplicitWorkspaceAsOneQuotedArgument() {
        val directories = listOf("C:\\work space\\東京", "C:\\", "C:\\work & space\\東京\\")
        directories.forEach { directory ->
            val commands = mutableListOf<List<String>>()
            val workspace = Path.of(directory)
            val manager = DesktopAutostartManager(
                commandResolver = { "C:\\Program Files\\VPN 東京\\vpn-control.exe" },
                platform = DesktopAutostartPlatform.WINDOWS,
                workspaceDirectory = workspace,
                commandRunner = { command ->
                    commands += command
                    DesktopAutostartCommandResult(if (command[1] == "/Create") 0 else 1, missingRegistration())
                },
            )
            assertTrue(manager.setEnabled(true).isSuccess)
            val create = commands.single { it.take(2) == listOf("schtasks", "/Create") }
            // Path normalizes trailing separators differently on native Windows and Unix hosts.
            val raw = workspace.toString()
            val expectedDirectory = raw + "\\".repeat(raw.takeLastWhile { it == '\\' }.length)
            assertEquals(
                "\"C:\\Program Files\\VPN 東京\\vpn-control.exe\" --autostart --state-dir \"$expectedDirectory\"",
                create[create.indexOf("/TR") + 1],
            )
            assertTrue(commands.none { it.first() !in setOf("schtasks", "reg") })
        }
    }

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
            assertTrue(manager.inspectEnabled())
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

            assertTrue(manager.inspectEnabled())
            assertFalse(Files.exists(tempDir.resolve("autostart").resolve("vpn-control.desktop")))
            assertTrue(Files.exists(systemdUserDir.resolve("vpn-control.service")))
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
    fun setEnabledWritesAndDeletesRecognizedOrdinaryWindowsScheduledTask() {
        val commands = mutableListOf<List<String>>()
        var taskEnabled = false
        var legacyRunEnabled = false
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.first() == "whoami.exe" -> DesktopAutostartCommandResult(0, "\"ME\\\\user\",\"S-1-5-21-1\"")
                    command.take(2) == listOf("schtasks", "/Query") -> {
                        DesktopAutostartCommandResult(if (taskEnabled) 0 else 1,
                            if (taskEnabled && command.contains("/XML")) windowsTaskXml(runLevel = "LeastPrivilege") else missingRegistration())
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
                        DesktopAutostartCommandResult(if (legacyRunEnabled) 0 else 1,
                            if (legacyRunEnabled) ownedRunEntry() else missingRegistration())
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
                "LIMITED",
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
    fun inspectionLeavesLegacyWindowsRunEntryUntouchedUntilExplicitEnable() {
        val commands = mutableListOf<List<String>>()
        var taskEnabled = false
        var legacyRunEnabled = true
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.first() == "whoami.exe" -> DesktopAutostartCommandResult(0, "\"ME\\\\user\",\"S-1-5-21-1\"")
                    command.take(2) == listOf("schtasks", "/Query") -> {
                        DesktopAutostartCommandResult(if (taskEnabled) 0 else 1,
                            if (taskEnabled && command.contains("/XML")) windowsTaskXml(runLevel = "LeastPrivilege") else missingRegistration())
                    }
                    command.take(2) == listOf("schtasks", "/Create") -> {
                        taskEnabled = true
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    command.take(2) == listOf("reg", "query") -> {
                        DesktopAutostartCommandResult(if (legacyRunEnabled) 0 else 1,
                            if (legacyRunEnabled) ownedRunEntry() else missingRegistration())
                    }
                    command.take(2) == listOf("reg", "delete") -> {
                        legacyRunEnabled = false
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    else -> DesktopAutostartCommandResult(1, "unexpected command")
                }
            },
        )

        assertTrue(manager.inspectEnabled())
        assertFalse(taskEnabled)
        assertTrue(legacyRunEnabled)
        assertTrue(commands.all { it.take(2) in listOf(listOf("schtasks", "/Query"), listOf("reg", "query")) })
        assertTrue(manager.isEnabled())
        assertFalse(taskEnabled)
        assertTrue(legacyRunEnabled)
        assertTrue(commands.all { it.take(2) in listOf(listOf("schtasks", "/Query",), listOf("reg", "query")) })
    }

    @Test
    fun explicitMigrationReplacesOnlyRevalidatedOwnedHighestTask() {
        val commands = mutableListOf<List<String>>()
        var taskXml = windowsTaskXml(runLevel = "HighestAvailable")
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.first() == "whoami.exe" -> DesktopAutostartCommandResult(0, "\"ME\\\\user\",\"S-1-5-21-1\"")
                    command.take(2) == listOf("schtasks", "/Query") -> DesktopAutostartCommandResult(0, taskXml)
                    command.take(2) == listOf("schtasks", "/Create") -> {
                        taskXml = windowsTaskXml(runLevel = "LeastPrivilege")
                        DesktopAutostartCommandResult(0, "ok")
                    }
                    else -> DesktopAutostartCommandResult(1, "unexpected")
                }
            },
        )

        assertTrue(manager.migrateOwnedWindowsHighestTaskToOrdinaryUser().isSuccess)
        assertEquals(2, commands.count { it.take(2) == listOf("schtasks", "/Query") })
        assertTrue(commands.single { it.take(2) == listOf("schtasks", "/Create") }.contains("LIMITED"))
    }

    @Test
    fun unknownSameNameTaskIsNeverMutated() {
        val commands = mutableListOf<List<String>>()
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                if (command.first() == "whoami.exe") DesktopAutostartCommandResult(0, "\"ME\\\\user\",\"S-1-5-21-1\"")
                else DesktopAutostartCommandResult(0, windowsTaskXml(command = "C:\\other\\tool.exe", runLevel = "HighestAvailable"))
            },
        )

        val result = manager.migrateOwnedWindowsHighestTaskToOrdinaryUser()

        assertTrue(result.isFailure)
        assertEquals("CONFLICT", result.exceptionOrNull()?.message)
        assertTrue(commands.all { it.take(2) == listOf("schtasks", "/Query") || it.first() == "whoami.exe" })
    }

    @Test
    fun taskXmlRejectsExternalEntitiesAndAmbiguousActions() {
        val external = """<!DOCTYPE Task [<!ENTITY x SYSTEM \"file:///not-read\">]><Task><Actions><Exec><Command>&x;</Command><Arguments>--autostart</Arguments></Exec></Actions></Task>"""
        assertTrue(WindowsTaskXml.inspect(external, "C:\\vpn-control.exe", "--autostart", "S-1-5-21-1") is WindowsTaskOwnership.Unknown)
        val ambiguous = windowsTaskXml(runLevel = "LeastPrivilege").replace("</Actions>",
            "<Exec><Command>C:\\vpn-control.exe</Command><Arguments>--autostart</Arguments></Exec></Actions>")
        assertTrue(WindowsTaskXml.inspect(ambiguous, "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe", "--autostart", "S-1-5-21-1") is WindowsTaskOwnership.Unknown)
    }

    @Test
    fun taskPathComparisonDoesNotCollapseDistinctUnicodeNames() {
        val composed = "C:\\Users\\me\\caf\u00e9\\vpn-control.exe"
        val decomposed = "C:\\Users\\me\\cafe\u0301\\vpn-control.exe"
        val ownership = WindowsTaskXml.inspect(windowsTaskXml(command = decomposed, runLevel = "LeastPrivilege"),
            composed, "--autostart", "S-1-5-21-1")
        assertTrue(ownership is WindowsTaskOwnership.Unknown)
    }

    @Test
    fun unrelatedRunValueIsNeverDeleted() {
        val commands = mutableListOf<List<String>>()
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { command ->
                commands += command
                when {
                    command.take(2) == listOf("schtasks", "/Query") -> DesktopAutostartCommandResult(1, missingRegistration())
                    command.take(2) == listOf("reg", "query") -> DesktopAutostartCommandResult(0,
                        "VPN Control    REG_SZ    \"C:\\other\\tool.exe\" --autostart")
                    else -> DesktopAutostartCommandResult(1, "unexpected")
                }
            },
        )
        assertTrue(manager.setEnabled(true).isFailure)
        assertTrue(commands.none { it.take(2) == listOf("reg", "delete") })
    }

    @Test
    fun taskQueryFailureIsNotTreatedAsAbsence() {
        val manager = DesktopAutostartManager(
            commandResolver = { "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe" },
            platform = DesktopAutostartPlatform.WINDOWS,
            commandRunner = { DesktopAutostartCommandResult(5, "Access is denied.") },
        )
        assertTrue(manager.setEnabled(true).isFailure)
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
        // .desktop string escaping is decoded before the Exec argument escaping.
        return "\"$escaped\"".replace("\\", "\\\\")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            .replace("%", "%%")
    }

    private fun windowsTaskXml(
        command: String = "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe",
        runLevel: String,
    ): String = """
        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
          <Principals><Principal id="Author"><UserId>S-1-5-21-1</UserId><LogonType>InteractiveToken</LogonType><RunLevel>$runLevel</RunLevel></Principal></Principals>
          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
          <Actions Context="Author"><Exec><Command>$command</Command><Arguments>--autostart</Arguments></Exec></Actions>
        </Task>
    """.trimIndent()

    private fun missingRegistration() = "ERROR: The system cannot find the file specified."

    private fun ownedRunEntry() =
        "VPN Control    REG_SZ    \"C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe\" --autostart"

    @Test
    fun desktopEntryFixtureKeepsBothBackslashEscapingLayers() {
        assertEquals("\"C:" + "\\".repeat(4) + "Apps" + "\\".repeat(4) + "vpn-control\"",
            desktopExecCommand("C:\\Apps\\vpn-control"))
        assertEquals("\"/opt/100%%/vpn-control\"", desktopExecCommand("/opt/100%/vpn-control"))
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
