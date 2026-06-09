package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Locale
import kotlin.io.path.name

internal class DesktopAutostartManager(
    private val configHome: Path = defaultConfigHome(),
    private val commandResolver: () -> String? = ::resolveLaunchCommand,
    private val platform: DesktopAutostartPlatform = currentAutostartPlatform(),
    private val commandRunner: (List<String>) -> DesktopAutostartCommandResult = ::runCommand,
    private val systemctlResolver: () -> Path? = ::platformSystemctl,
) {
    private val autostartFile = configHome
        .resolve("autostart")
        .resolve("vpn-control.desktop")
    private val systemdServiceFile = configHome
        .resolve("systemd")
        .resolve("user")
        .resolve("vpn-control.service")
    private val systemdWantsFile = systemdServiceFile.parent
        .resolve("default.target.wants")
        .resolve("vpn-control.service")

    fun isEnabled(): Boolean {
        return when (platform) {
            DesktopAutostartPlatform.LINUX -> isLinuxAutostartEnabled()
            DesktopAutostartPlatform.WINDOWS -> isWindowsTaskEnabled() || migrateLegacyWindowsRunEntry()
            DesktopAutostartPlatform.UNSUPPORTED -> false
        }
    }

    fun setEnabled(enabled: Boolean): Result<Boolean> {
        return runCatching {
            when (platform) {
                DesktopAutostartPlatform.LINUX -> setLinuxAutostartEnabled(enabled)
                DesktopAutostartPlatform.WINDOWS -> setWindowsTaskEnabled(enabled)
                DesktopAutostartPlatform.UNSUPPORTED -> error("Start on login is not supported on this desktop platform.")
            }
        }
    }

    private fun isLinuxAutostartEnabled(): Boolean {
        val xdgEntryExists = pathExistsOrSymlink(autostartFile)
        val xdgEntryEnabled = isXdgAutostartEnabled()
        val legacySystemdExists = legacyLinuxSystemdAutostartExists()
        if (legacySystemdExists) {
            if (!xdgEntryExists || !xdgEntryEnabled) {
                runCatching { setXdgAutostartEnabled(true) }
            }
            deleteLegacyLinuxSystemdAutostart()
        }
        return isXdgAutostartEnabled()
    }

    private fun setLinuxAutostartEnabled(enabled: Boolean): Boolean {
        return if (enabled) {
            setXdgAutostartEnabled(true)
            deleteLegacyLinuxSystemdAutostart()
            true
        } else {
            Files.deleteIfExists(autostartFile)
            deleteLegacyLinuxSystemdAutostart()
            false
        }
    }

    private fun isXdgAutostartEnabled(): Boolean {
        if (!Files.exists(autostartFile)) return false
        val content = runCatching { Files.readString(autostartFile) }.getOrDefault("")
        if (content.lineSequence().any { line ->
            line.trim().equals("Hidden=true", ignoreCase = true)
        }) {
            return false
        }
        val command = desktopEntryExecCommand(content) ?: return false
        return runCatching { Files.isExecutable(Paths.get(command)) }.getOrDefault(false)
    }

    private fun setXdgAutostartEnabled(enabled: Boolean): Boolean {
        return if (enabled) {
            val command = commandResolver()?.takeIf(String::isNotBlank)
                ?: error("Could not resolve the desktop app launcher path.")
            Files.createDirectories(autostartFile.parent)
            Files.writeString(autostartFile, desktopEntry(command))
            true
        } else {
            Files.deleteIfExists(autostartFile)
            false
        }
    }

    private fun legacyLinuxSystemdAutostartExists(): Boolean {
        return pathExistsOrSymlink(systemdServiceFile) || pathExistsOrSymlink(systemdWantsFile)
    }

    private fun deleteLegacyLinuxSystemdAutostart() {
        if (!legacyLinuxSystemdAutostartExists()) return
        disableSystemdUserService()
        Files.deleteIfExists(systemdWantsFile)
        Files.deleteIfExists(systemdServiceFile)
        reloadSystemdUser()
    }

    private fun disableSystemdUserService() {
        val systemctl = systemctlResolver() ?: return
        commandRunner(listOf(systemctl.toString(), "--user", "disable", "vpn-control.service"))
    }

    private fun pathExistsOrSymlink(path: Path): Boolean {
        return Files.exists(path) || Files.isSymbolicLink(path)
    }

    private fun reloadSystemdUser() {
        val systemctl = systemctlResolver() ?: return
        commandRunner(listOf(systemctl.toString(), "--user", "daemon-reload"))
    }

    private fun desktopEntry(command: String): String {
        return """
            |[Desktop Entry]
            |Type=Application
            |Version=1.0
            |Name=VPN Control
            |Comment=Start VPN Control at login
            |Exec=${quoteDesktopExec(command)} --autostart
            |Terminal=false
            |Categories=Network;
            |X-GNOME-Autostart-enabled=true
            |
        """.trimMargin()
    }

    private fun isWindowsRunEnabled(): Boolean {
        return commandRunner(
            listOf("reg", "query", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE),
        ).exitCode == 0
    }

    private fun isWindowsTaskEnabled(): Boolean {
        return commandRunner(
            listOf("schtasks", "/Query", "/TN", WINDOWS_TASK_NAME),
        ).exitCode == 0
    }

    private fun migrateLegacyWindowsRunEntry(): Boolean {
        if (!isWindowsRunEnabled()) {
            return false
        }
        return setWindowsTaskEnabled(true)
    }

    private fun setWindowsTaskEnabled(enabled: Boolean): Boolean {
        if (enabled) {
            val command = commandResolver()?.takeIf(String::isNotBlank)
                ?: error("Could not resolve the desktop app launcher path.")
            val result = commandRunner(
                listOf(
                    "schtasks",
                    "/Create",
                    "/TN",
                    WINDOWS_TASK_NAME,
                    "/SC",
                    "ONLOGON",
                    "/TR",
                    windowsScheduledTaskCommand(command),
                    "/RL",
                    "HIGHEST",
                    "/F",
                ),
            )
            if (result.exitCode != 0) {
                error(result.output.ifBlank { "Failed to create Windows startup scheduled task." })
            }
            deleteWindowsRunEntryIfPresent()
            return true
        }

        if (isWindowsTaskEnabled()) {
            val result = commandRunner(
                listOf("schtasks", "/Delete", "/TN", WINDOWS_TASK_NAME, "/F"),
            )
            if (result.exitCode != 0) {
                error(result.output.ifBlank { "Failed to delete Windows startup scheduled task." })
            }
        }
        deleteWindowsRunEntryIfPresent()
        return false
    }

    private fun deleteWindowsRunEntryIfPresent() {
        if (!isWindowsRunEnabled()) return
        val result = commandRunner(
            listOf("reg", "delete", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE, "/f"),
        )
        if (result.exitCode != 0) {
            error(result.output.ifBlank { "Failed to delete Windows startup registry entry." })
        }
    }

    companion object {
        fun default(): DesktopAutostartManager = DesktopAutostartManager()

        private const val WINDOWS_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        private const val WINDOWS_RUN_VALUE = "VPN Control"
        private const val WINDOWS_TASK_NAME = "VPN Control"

        private fun defaultConfigHome(): Path {
            val xdgConfigHome = System.getenv("XDG_CONFIG_HOME")
                ?.split(':')
                ?.firstOrNull(String::isNotBlank)
            return if (xdgConfigHome != null) {
                Paths.get(xdgConfigHome)
            } else {
                Paths.get(System.getProperty("user.home"), ".config")
            }
        }

        private fun resolveLaunchCommand(): String? {
            platformLaunchCandidates().firstOrNull(Files::isExecutable)?.let { return it.toString() }
            val command = ProcessHandle.current().info().command().orElse(null)?.takeIf(String::isNotBlank)
                ?: return null
            val commandName = runCatching { Paths.get(command).name.lowercase(Locale.ROOT) }.getOrDefault("")
            if (commandName == "java" || commandName == "java.exe" || commandName == "javaw.exe") {
                return null
            }
            return command
        }

        private fun platformLaunchCandidates(): List<Path> {
            return when (currentAutostartPlatform()) {
                DesktopAutostartPlatform.LINUX -> listOf(
                    Paths.get("/usr/local/bin/vpn-control"),
                    Paths.get("/opt/vpn-control/bin/vpn-control"),
                )
                DesktopAutostartPlatform.WINDOWS -> listOfNotNull(
                    System.getenv("LOCALAPPDATA")?.let { Paths.get(it, "vpn-control", "vpn-control.exe") },
                    System.getenv("LOCALAPPDATA")?.let { Paths.get(it, "Programs", "vpn-control", "vpn-control.exe") },
                    System.getenv("ProgramFiles")?.let { Paths.get(it, "vpn-control", "vpn-control.exe") },
                    System.getenv("ProgramFiles(x86)")?.let { Paths.get(it, "vpn-control", "vpn-control.exe") },
                )
                DesktopAutostartPlatform.UNSUPPORTED -> emptyList()
            }
        }

        private fun windowsScheduledTaskCommand(command: String): String {
            return "${quoteWindowsCommandPath(command)} --autostart"
        }

        private fun quoteWindowsCommandPath(value: String): String {
            return "\"${value.replace("\"", "\\\"")}\""
        }

        private fun quoteDesktopExec(value: String): String {
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

        private fun desktopEntryExecCommand(content: String): String? {
            val execValue = content.lineSequence()
                .map(String::trim)
                .firstOrNull { it.startsWith("Exec=", ignoreCase = true) }
                ?.substringAfter('=')
                ?.trim()
                ?: return null
            return parseDesktopExecCommand(execValue)
        }

        private fun parseDesktopExecCommand(value: String): String? {
            if (value.isBlank()) return null
            if (value.first() != '"') {
                return value.takeWhile { !it.isWhitespace() }.takeIf(String::isNotBlank)
            }
            val parsed = buildString {
                var index = 1
                while (index < value.length) {
                    val char = value[index]
                    when {
                        char == '"' -> return@buildString
                        char == '\\' && index + 1 < value.length -> {
                            append(value[index + 1])
                            index += 1
                        }
                        else -> append(char)
                    }
                    index += 1
                }
            }
            return parsed.takeIf(String::isNotBlank)
        }

        private fun platformSystemctl(): Path? {
            return listOf(
                Paths.get("/usr/bin/systemctl"),
                Paths.get("/bin/systemctl"),
            ).firstOrNull(Files::isExecutable)
        }

        private fun runCommand(command: List<String>): DesktopAutostartCommandResult {
            return runCatching {
                val process = ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().use { it.readText() }
                DesktopAutostartCommandResult(process.waitFor(), output)
            }.getOrElse { error ->
                DesktopAutostartCommandResult(exitCode = -1, output = error.message.orEmpty())
            }
        }
    }
}

internal enum class DesktopAutostartPlatform {
    LINUX,
    WINDOWS,
    UNSUPPORTED,
}

internal data class DesktopAutostartCommandResult(
    val exitCode: Int,
    val output: String,
)

internal fun currentAutostartPlatform(): DesktopAutostartPlatform {
    val osName = System.getProperty("os.name").lowercase(Locale.ROOT)
    return when {
        osName.contains("win") -> DesktopAutostartPlatform.WINDOWS
        osName.contains("linux") -> DesktopAutostartPlatform.LINUX
        else -> DesktopAutostartPlatform.UNSUPPORTED
    }
}
