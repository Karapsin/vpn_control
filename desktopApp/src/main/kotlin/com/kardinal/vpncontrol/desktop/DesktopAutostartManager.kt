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
    private val executableChecker: (Path) -> Boolean = Files::isExecutable,
    private val environment: () -> Map<String, String> = System::getenv,
    private val workspaceDirectory: Path? = DesktopWorkspacePaths.overrideDirectory(),
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
    private val i3ConfigFile = configHome
        .resolve("i3")
        .resolve("config")

    fun isEnabled(): Boolean {
        return when (platform) {
            DesktopAutostartPlatform.LINUX -> isLinuxAutostartEnabled()
            DesktopAutostartPlatform.WINDOWS -> isWindowsTaskEnabled() || migrateLegacyWindowsRunEntry()
            DesktopAutostartPlatform.UNSUPPORTED -> false
        }
    }

    /** Queries configuration without migrating entries, deleting files, or repairing i3 setup. */
    fun inspectEnabled(): Boolean = when (platform) {
        DesktopAutostartPlatform.LINUX -> isXdgAutostartEnabled() || isI3AutostartEnabled() || legacyLinuxSystemdAutostartExists()
        DesktopAutostartPlatform.WINDOWS -> isWindowsTaskEnabled() || isWindowsRunEnabled()
        DesktopAutostartPlatform.UNSUPPORTED -> false
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
        val currentXdgEntryEnabled = isXdgAutostartEnabled()
        if (currentXdgEntryEnabled && isI3Session() && !isI3AutostartEnabled()) {
            runCatching { setI3AutostartEnabled(true) }
        }
        return currentXdgEntryEnabled || isI3AutostartEnabled()
    }

    private fun setLinuxAutostartEnabled(enabled: Boolean): Boolean {
        return if (enabled) {
            setXdgAutostartEnabled(true)
            if (isI3Session()) {
                setI3AutostartEnabled(true)
            }
            deleteLegacyLinuxSystemdAutostart()
            true
        } else {
            Files.deleteIfExists(autostartFile)
            setI3AutostartEnabled(false)
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
        return runCatching { executableChecker(Paths.get(command)) }.getOrDefault(false)
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

    private fun isI3AutostartEnabled(): Boolean {
        if (!Files.exists(i3ConfigFile)) return false
        val content = runCatching { Files.readString(i3ConfigFile) }.getOrDefault("")
        val block = managedI3AutostartBlock(content) ?: return false
        return block.lineSequence().any { line ->
            val command = i3ExecCommand(line) ?: return@any false
            line.contains("--autostart") &&
                runCatching { executableChecker(Paths.get(command)) }.getOrDefault(false)
        }
    }

    private fun setI3AutostartEnabled(enabled: Boolean): Boolean {
        if (enabled) {
            val command = commandResolver()?.takeIf(String::isNotBlank)
                ?: error("Could not resolve the desktop app launcher path.")
            Files.createDirectories(i3ConfigFile.parent)
            val content = runCatching { Files.readString(i3ConfigFile) }.getOrDefault("")
            Files.writeString(i3ConfigFile, withManagedI3AutostartBlock(content, command))
            return true
        }

        if (!Files.exists(i3ConfigFile)) return false
        val content = runCatching { Files.readString(i3ConfigFile) }.getOrDefault("")
        if (managedI3AutostartBlock(content) == null) return false
        Files.writeString(i3ConfigFile, withoutManagedI3AutostartBlock(content))
        return false
    }

    private fun isI3Session(): Boolean {
        val env = environment()
        if (!env["I3SOCK"].isNullOrBlank()) return true
        return listOf(env["XDG_CURRENT_DESKTOP"], env["DESKTOP_SESSION"])
            .filterNotNull()
            .any { value ->
                value.lowercase(Locale.ROOT)
                    .split(':', ';', ',', ' ')
                    .any { it == "i3" }
            }
    }

    private fun managedI3AutostartBlock(content: String): String? {
        val lines = content.lines()
        val start = lines.indexOfFirst { it.trim() == I3_AUTOSTART_BEGIN }
        if (start < 0) return null
        val end = lines.drop(start + 1).indexOfFirst { it.trim() == I3_AUTOSTART_END }
        if (end < 0) return null
        return lines.subList(start + 1, start + 1 + end).joinToString("\n")
    }

    private fun withManagedI3AutostartBlock(content: String, command: String): String {
        val stripped = withoutManagedI3AutostartBlock(content).trimEnd()
        val block = """
            |$I3_AUTOSTART_BEGIN
            |${i3AutostartExecLine(command, workspaceDirectory)}
            |$I3_AUTOSTART_END
        """.trimMargin()
        return listOf(stripped, block)
            .filter(String::isNotBlank)
            .joinToString("\n\n")
            .let { if (it.isBlank()) "" else "$it\n" }
    }

    private fun withoutManagedI3AutostartBlock(content: String): String {
        val kept = mutableListOf<String>()
        var inBlock = false
        content.lines().forEach { line ->
            when {
                line.trim() == I3_AUTOSTART_BEGIN -> inBlock = true
                inBlock && line.trim() == I3_AUTOSTART_END -> inBlock = false
                !inBlock -> kept += line
            }
        }
        return kept.joinToString("\n").trimEnd() + "\n"
    }

    private fun i3ExecCommand(line: String): String? {
        val trimmed = line.trim()
        if (!trimmed.startsWith("exec ")) return null
        val command = trimmed
            .removePrefix("exec")
            .trim()
            .removePrefix("--no-startup-id")
            .trim()
        return i3ShellWrapperCommand(command)
    }

    private fun i3ShellWrapperCommand(command: String): String? {
        val words = splitShellWords(command) ?: return null
        if (words.size != 5 && words.size != 6) return null
        if (words[0] != "sh" || words[1] != "-c") return null
        val script = if (words.size == 5) I3_SHELL_SCRIPT else I3_WORKSPACE_SHELL_SCRIPT
        if (words[2] != script || words[3] != I3_SHELL_ARG0) return null
        return words[4].takeIf(String::isNotBlank)
    }

    private fun splitShellWords(value: String): List<String>? {
        val words = mutableListOf<String>()
        val current = StringBuilder()
        var index = 0
        var quote: Char? = null
        var tokenStarted = false

        while (index < value.length) {
            val char = value[index]
            when {
                quote == '\'' -> {
                    if (char == '\'') {
                        quote = null
                    } else {
                        current.append(char)
                    }
                }
                quote == '"' -> {
                    when {
                        char == '"' -> quote = null
                        char == '\\' && index + 1 < value.length -> {
                            current.append(value[index + 1])
                            index += 1
                        }
                        else -> current.append(char)
                    }
                }
                char.isWhitespace() -> {
                    if (tokenStarted) {
                        words += current.toString()
                        current.clear()
                        tokenStarted = false
                    }
                }
                char == '\'' || char == '"' -> {
                    quote = char
                    tokenStarted = true
                }
                char == '\\' && index + 1 < value.length -> {
                    current.append(value[index + 1])
                    index += 1
                    tokenStarted = true
                }
                else -> {
                    current.append(char)
                    tokenStarted = true
                }
            }
            index += 1
        }

        if (quote != null) return null
        if (tokenStarted) words += current.toString()
        return words
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
            |Exec=${quoteDesktopExec(command)} --autostart${workspaceDirectory?.let { " --state-dir ${quoteDesktopExec(it.toString())}" } ?: ""}
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
                    windowsScheduledTaskCommand(command, workspaceDirectory),
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
        private const val I3_AUTOSTART_BEGIN = "# VPN Control autostart: begin"
        private const val I3_AUTOSTART_END = "# VPN Control autostart: end"
        private const val I3_SHELL_SCRIPT = "exec \"\$1\" --autostart"
        private const val I3_WORKSPACE_SHELL_SCRIPT = "exec \"\$1\" --autostart --state-dir \"\$2\""
        private const val I3_SHELL_ARG0 = "vpn-control-i3"

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

        private fun windowsScheduledTaskCommand(command: String, workspaceDirectory: Path?): String {
            return "${quoteWindowsCommandPath(command)} --autostart" +
                (workspaceDirectory?.let { " --state-dir ${quoteWindowsCommandPath(it.toString())}" } ?: "")
        }

        private fun quoteWindowsCommandPath(value: String): String {
            // Windows argv parsing doubles backslashes before quotes and the closing quote.
            return buildString {
                append('"')
                var backslashes = 0
                value.forEach { char ->
                    if (char == '\\') {
                        backslashes++
                    } else {
                        repeat(if (char == '"') backslashes * 2 + 1 else backslashes) { append('\\') }
                        append(char)
                        backslashes = 0
                    }
                }
                repeat(backslashes * 2) { append('\\') }
                append('"')
            }
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
            // Desktop-entry string escaping is a separate layer, decoded before Exec quoting.
            return "\"$escaped\"".replace("\\", "\\\\")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                .replace("%", "%%")
        }

        private fun i3AutostartExecLine(command: String, workspaceDirectory: Path?): String {
            val script = if (workspaceDirectory == null) I3_SHELL_SCRIPT else I3_WORKSPACE_SHELL_SCRIPT
            return "exec --no-startup-id sh -c ${quoteI3ShellArg(script)} " +
                "$I3_SHELL_ARG0 ${quoteI3ShellArg(command)}" +
                (workspaceDirectory?.let { " ${quoteI3ShellArg(it.toString())}" } ?: "")
        }

        private fun quoteI3ShellArg(value: String): String {
            return "'${value.replace("'", "'\"'\"'")}'"
        }

        private fun desktopEntryExecCommand(content: String): String? {
            val execValue = content.lineSequence()
                .map(String::trim)
                .firstOrNull { it.startsWith("Exec=", ignoreCase = true) }
                ?.substringAfter('=')
                ?.trim()
                ?: return null
            val decoded = buildString {
                var index = 0
                while (index < execValue.length) {
                    val char = execValue[index++]
                    if (char == '\\' && index < execValue.length) {
                        val escaped = execValue[index++]
                        append(when (escaped) {
                            's' -> ' '
                            'n' -> '\n'
                            'r' -> '\r'
                            't' -> '\t'
                            '\\' -> '\\'
                            else -> { append('\\'); escaped }
                        })
                    } else append(char)
                }
            }
            return parseDesktopExecCommand(decoded)?.replace("%%", "%")
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
