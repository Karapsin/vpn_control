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
) {
    private val autostartFile = configHome
        .resolve("autostart")
        .resolve("vpn-control.desktop")

    fun isEnabled(): Boolean {
        return when (platform) {
            DesktopAutostartPlatform.LINUX -> isXdgAutostartEnabled()
            DesktopAutostartPlatform.WINDOWS -> isWindowsRunEnabled()
            DesktopAutostartPlatform.UNSUPPORTED -> false
        }
    }

    fun setEnabled(enabled: Boolean): Result<Boolean> {
        return runCatching {
            when (platform) {
                DesktopAutostartPlatform.LINUX -> setXdgAutostartEnabled(enabled)
                DesktopAutostartPlatform.WINDOWS -> setWindowsRunEnabled(enabled)
                DesktopAutostartPlatform.UNSUPPORTED -> error("Start on login is not supported on this desktop platform.")
            }
        }
    }

    private fun isXdgAutostartEnabled(): Boolean {
        if (!Files.exists(autostartFile)) return false
        val content = runCatching { Files.readString(autostartFile) }.getOrDefault("")
        return !content.lineSequence().any { line ->
            line.trim().equals("Hidden=true", ignoreCase = true)
        }
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

    private fun desktopEntry(command: String): String {
        return """
            |[Desktop Entry]
            |Type=Application
            |Version=1.0
            |Name=VPN Control
            |Comment=Start VPN Control at login
            |Exec=${quoteDesktopExec(command)}
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

    private fun setWindowsRunEnabled(enabled: Boolean): Boolean {
        if (enabled) {
            val command = commandResolver()?.takeIf(String::isNotBlank)
                ?: error("Could not resolve the desktop app launcher path.")
            val result = commandRunner(
                listOf(
                    "reg",
                    "add",
                    WINDOWS_RUN_KEY,
                    "/v",
                    WINDOWS_RUN_VALUE,
                    "/t",
                    "REG_SZ",
                    "/d",
                    quoteWindowsRunCommand(command),
                    "/f",
                ),
            )
            if (result.exitCode != 0) {
                error(result.output.ifBlank { "Failed to write Windows startup registry entry." })
            }
            return true
        }

        if (!isWindowsRunEnabled()) return false
        val result = commandRunner(
            listOf("reg", "delete", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE, "/f"),
        )
        if (result.exitCode != 0) {
            error(result.output.ifBlank { "Failed to delete Windows startup registry entry." })
        }
        return false
    }

    companion object {
        fun default(): DesktopAutostartManager = DesktopAutostartManager()

        private const val WINDOWS_RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        private const val WINDOWS_RUN_VALUE = "VPN Control"

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

        private fun quoteWindowsRunCommand(value: String): String {
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
