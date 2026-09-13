package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Locale
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
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
            // Inspection is deliberately read-only. A user explicitly enabling startup may
            // migrate the legacy Run entry, but ordinary application startup never does.
            DesktopAutostartPlatform.WINDOWS -> isWindowsTaskEnabled() || isWindowsRunEnabled()
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

    /**
     * Explicit repair only. Startup inspection deliberately never calls this: task replacement
     * needs a final ownership recheck and is not safe to infer from a task name alone.
     */
    internal fun migrateOwnedWindowsHighestTaskToOrdinaryUser(): Result<Boolean> = runCatching {
        check(platform == DesktopAutostartPlatform.WINDOWS) { "Windows autostart is unavailable on this platform." }
        val command = commandResolver()?.takeIf(String::isNotBlank)
            ?: error("Could not resolve the desktop app launcher path.")
        val first = inspectWindowsTaskOwnership(command)
        check(first is WindowsTaskOwnership.OwnedHighest) { first.reason }
        // schtasks has no compare-and-swap registration. This narrows, but cannot eliminate, a
        // concurrent replacement race; the caller must keep this explicit repair inactive until
        // a coordinator supplies an atomic Task Scheduler operation.
        val second = inspectWindowsTaskOwnership(command)
        check(second is WindowsTaskOwnership.OwnedHighest && second.xml == first.xml) {
            "CONFLICT"
        }
        createWindowsTask(command, replaceOwned = true)
        true
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

    private fun isWindowsRunEnabled(): Boolean = commandResolver()?.takeIf(String::isNotBlank)?.let { command ->
        inspectWindowsRunOwnership(command) is WindowsRunOwnership.Owned
    } ?: false

    private fun isWindowsTaskEnabled(): Boolean = commandResolver()?.takeIf(String::isNotBlank)?.let { command ->
        when (inspectWindowsTaskOwnership(command)) {
            is WindowsTaskOwnership.OwnedHighest, is WindowsTaskOwnership.OwnedOrdinary -> true
            else -> false
        }
    } ?: false

    private fun setWindowsTaskEnabled(enabled: Boolean): Boolean {
        if (enabled) {
            val command = commandResolver()?.takeIf(String::isNotBlank)
                ?: error("Could not resolve the desktop app launcher path.")
            // Validate a same-named legacy value before creating a task; otherwise a later
            // ownership failure would leave a partial migration behind.
            when (val runOwnership = inspectWindowsRunOwnership(command)) {
                WindowsRunOwnership.Absent, WindowsRunOwnership.Owned -> Unit
                is WindowsRunOwnership.Unknown -> error(runOwnership.reason)
            }
            when (val ownership = inspectWindowsTaskOwnership(command)) {
                is WindowsTaskOwnership.Absent -> createWindowsTask(command)
                is WindowsTaskOwnership.OwnedOrdinary -> Unit
                is WindowsTaskOwnership.OwnedHighest -> error("CONFLICT")
                is WindowsTaskOwnership.Unknown -> error(ownership.reason)
            }
            deleteWindowsRunEntryIfPresent()
            return true
        }

        val command = commandResolver()?.takeIf(String::isNotBlank)
            ?: error("Could not resolve the desktop app launcher path.")
        when (val ownership = inspectWindowsTaskOwnership(command)) {
            is WindowsTaskOwnership.Absent -> Unit
            is WindowsTaskOwnership.OwnedOrdinary, is WindowsTaskOwnership.OwnedHighest -> {
            val result = commandRunner(
                listOf("schtasks", "/Delete", "/TN", WINDOWS_TASK_NAME, "/F"),
            )
            if (result.exitCode != 0) {
                error(result.output.ifBlank { "Failed to delete Windows startup scheduled task." })
            }
            }
            is WindowsTaskOwnership.Unknown -> error(ownership.reason)
        }
        deleteWindowsRunEntryIfPresent()
        return false
    }

    private fun createWindowsTask(command: String, replaceOwned: Boolean = false) {
        val arguments = mutableListOf(
            "schtasks", "/Create", "/TN", WINDOWS_TASK_NAME, "/SC", "ONLOGON",
            "/TR", windowsScheduledTaskCommand(command, workspaceDirectory),
            "/RL", "LIMITED",
        )
        if (replaceOwned) arguments += "/F"
        val result = commandRunner(
            arguments,
        )
        if (result.exitCode != 0) error(result.output.ifBlank { "Failed to create Windows startup scheduled task." })
    }

    private fun inspectWindowsTaskOwnership(command: String): WindowsTaskOwnership {
        val result = commandRunner(listOf("schtasks", "/Query", "/TN", WINDOWS_TASK_NAME, "/XML"))
        if (result.exitCode != 0) return if (WindowsAutostartReadOnlyProbe.taskAbsent(commandRunner)) WindowsTaskOwnership.Absent
        else WindowsTaskOwnership.Unknown("UNAVAILABLE")
        val sid = currentWindowsUserSid()
            ?: return WindowsTaskOwnership.Unknown("UNAVAILABLE")
        return WindowsTaskXml.inspect(result.output, command, windowsTaskArguments(workspaceDirectory), sid)
    }

    private fun inspectWindowsRunOwnership(command: String): WindowsRunOwnership {
        val result = commandRunner(listOf("reg", "query", WINDOWS_RUN_KEY, "/v", WINDOWS_RUN_VALUE))
        if (result.exitCode != 0) return if (WindowsAutostartReadOnlyProbe.runValueAbsent(commandRunner)) WindowsRunOwnership.Absent
        else WindowsRunOwnership.Unknown("UNAVAILABLE")
        val values = result.output.lineSequence().map(String::trim).filter { it.isNotEmpty() }
            .mapNotNull { WINDOWS_RUN_ENTRY.matchEntire(it)?.groupValues?.get(1) }.toList()
        return when {
            values.size != 1 -> WindowsRunOwnership.Unknown("CONFLICT")
            windowsIdentity(values.single()) != windowsIdentity(windowsScheduledTaskCommand(command, workspaceDirectory)) ->
                WindowsRunOwnership.Unknown("CONFLICT")
            else -> WindowsRunOwnership.Owned
        }
    }

    private fun currentWindowsUserSid(): String? {
        val result = commandRunner(listOf("whoami.exe", "/user", "/fo", "csv", "/nh"))
        if (result.exitCode != 0) return null
        return WHOAMI_SID.matchEntire(result.output.trim())?.groupValues?.get(1)
    }

    private fun deleteWindowsRunEntryIfPresent() {
        val command = commandResolver()?.takeIf(String::isNotBlank)
            ?: error("UNAVAILABLE")
        when (val ownership = inspectWindowsRunOwnership(command)) {
            WindowsRunOwnership.Absent -> return
            WindowsRunOwnership.Owned -> Unit
            is WindowsRunOwnership.Unknown -> error(ownership.reason)
        }
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
        private val WINDOWS_RUN_ENTRY = Regex("^VPN Control\\s+REG_SZ\\s+(.+)$", RegexOption.IGNORE_CASE)
        private val WHOAMI_SID = Regex("^\"[^\"]*\",\"(S-[0-9]+-(?:[0-9]+-)*[0-9]+)\"$")
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

        private fun windowsTaskArguments(workspaceDirectory: Path?): String = "--autostart" +
            (workspaceDirectory?.let { " --state-dir ${quoteWindowsCommandPath(it.toString())}" } ?: "")

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

internal sealed interface WindowsTaskOwnership {
    object Absent : WindowsTaskOwnership
    data class OwnedHighest(val xml: String) : WindowsTaskOwnership
    object OwnedOrdinary : WindowsTaskOwnership
    data class Unknown(override val reason: String) : WindowsTaskOwnership
    val reason: String get() = when (this) {
        Absent -> "NOT_FOUND"
        is OwnedHighest -> "CONFLICT"
        OwnedOrdinary -> "OK"
        is Unknown -> this.reason
    }
}

private sealed interface WindowsRunOwnership {
    object Absent : WindowsRunOwnership
    object Owned : WindowsRunOwnership
    data class Unknown(val reason: String) : WindowsRunOwnership
}

/** Bounded, entity-free recognition of one task definition; it never mutates Task Scheduler. */
internal object WindowsTaskXml {
    private const val MAX_XML_BYTES = 128 * 1024

    fun inspect(xml: String, expectedCommand: String, expectedArguments: String, expectedUserSid: String): WindowsTaskOwnership {
        if (xml.toByteArray(Charsets.UTF_8).size !in 1..MAX_XML_BYTES) {
            return WindowsTaskOwnership.Unknown("CONFLICT")
        }
        val document = runCatching {
            DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
                setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)
                setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
                setFeature("http://xml.org/sax/features/external-general-entities", false)
                setFeature("http://xml.org/sax/features/external-parameter-entities", false)
                setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
                setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
                setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
                isXIncludeAware = false
                isExpandEntityReferences = false
            }.newDocumentBuilder().parse(org.xml.sax.InputSource(xml.reader()))
        }.getOrElse {
            return WindowsTaskOwnership.Unknown("CONFLICT")
        }
        val root = document.documentElement ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (root.name() != "Task") return WindowsTaskOwnership.Unknown("CONFLICT")
        val actions = elements(document, "Actions").singleOrNull()
            ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (directChildren(actions).any { it.name() != "Exec" })
            return WindowsTaskOwnership.Unknown("CONFLICT")
        val exec = directChildren(actions).singleOrNull()
            ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (directChildren(exec).any { it.name() !in setOf("Command", "Arguments", "WorkingDirectory") })
            return WindowsTaskOwnership.Unknown("CONFLICT")
        val command = directText(exec, "Command") ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        val arguments = directText(exec, "Arguments") ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        val workingDirectory = directText(exec, "WorkingDirectory")
        if (workingDirectory != null && workingDirectory.isNotBlank())
            return WindowsTaskOwnership.Unknown("CONFLICT")
        if (windowsIdentity(command) != windowsIdentity(expectedCommand) || arguments != expectedArguments)
            return WindowsTaskOwnership.Unknown("CONFLICT")
        val triggers = elements(document, "Triggers").singleOrNull()
            ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (directChildren(triggers).any { it.name() != "LogonTrigger" })
            return WindowsTaskOwnership.Unknown("CONFLICT")
        val trigger = directChildren(triggers).singleOrNull()
            ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (directText(trigger, "Enabled")?.equals("true", ignoreCase = true) != true)
            return WindowsTaskOwnership.Unknown("CONFLICT")
        val principal = elements(document, "Principal").singleOrNull()
            ?: return WindowsTaskOwnership.Unknown("CONFLICT")
        if (directText(principal, "UserId") != expectedUserSid || directText(principal, "LogonType") != "InteractiveToken")
            return WindowsTaskOwnership.Unknown("CONFLICT")
        return when (directText(principal, "RunLevel")) {
            "HighestAvailable" -> WindowsTaskOwnership.OwnedHighest(xml)
            "LeastPrivilege" -> WindowsTaskOwnership.OwnedOrdinary
            else -> WindowsTaskOwnership.Unknown("CONFLICT")
        }
    }

    private fun elements(document: org.w3c.dom.Document, name: String): List<org.w3c.dom.Element> =
        (0 until document.getElementsByTagNameNS("*", name).length).map { index ->
            document.getElementsByTagNameNS("*", name).item(index) as org.w3c.dom.Element
        }

    private fun directChildren(parent: org.w3c.dom.Element): List<org.w3c.dom.Element> =
        (0 until parent.childNodes.length).mapNotNull { parent.childNodes.item(it) as? org.w3c.dom.Element }

    private fun directText(parent: org.w3c.dom.Element, name: String): String? =
        directChildren(parent).filter { it.name() == name }.singleOrNull()?.textContent

    private fun org.w3c.dom.Element.name(): String = localName ?: nodeName.substringAfterLast(':')

}

/** Windows comparisons are case-insensitive, but NTFS preserves Unicode code-point distinctions. */
private fun windowsIdentity(value: String): String = value.lowercase(Locale.ROOT)

internal enum class DesktopAutostartPlatform {
    LINUX,
    WINDOWS,
    UNSUPPORTED,
}

internal data class DesktopAutostartCommandResult(
    val exitCode: Int,
    val output: String,
)

/**
 * Fixed Windows-native absence checks used only after a localized CLI query fails.
 * Any result other than the exact marker remains unavailable; the probes never establish
 * ownership, alter a registration, or receive caller-controlled input.
 */
internal object WindowsAutostartReadOnlyProbe {
    private const val ABSENT = "ABSENT"
    private val powershellPrefix = listOf(
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
    )

    fun taskAbsent(commandRunner: (List<String>) -> DesktopAutostartCommandResult): Boolean =
        run(commandRunner, taskAbsenceScript)

    fun runValueAbsent(commandRunner: (List<String>) -> DesktopAutostartCommandResult): Boolean =
        run(commandRunner, runValueAbsenceScript)

    private fun run(commandRunner: (List<String>) -> DesktopAutostartCommandResult, script: String): Boolean {
        val result = commandRunner(powershellPrefix + script)
        return result.exitCode == 0 && result.output == ABSENT
    }

    // Actual Windows Task Scheduler evidence maps a missing GetTask result to
    // FileNotFoundException/HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND). The inner try scopes
    // that classification to GetTask only, so Connect/GetFolder failures remain unavailable.
    internal val taskMissingClassifierScript = """
        function Test-MissingTask([System.Exception]${'$'}exception) {
            ${'$'}current=${'$'}exception
            for (${ '$' }depth=0; ${ '$' }depth -lt 8 -and ${ '$' }null -ne ${ '$' }current; ${ '$' }depth+=1) {
                if ((${ '$' }current -is [System.IO.FileNotFoundException] -or ${ '$' }current -is [System.Runtime.InteropServices.COMException]) -and ${ '$' }current.HResult -eq -2147024894) { return ${ '$' }true }
                ${'$'}current=${'$'}current.InnerException
            }
            return ${'$'}false
        }
    """.trimIndent()

    internal val taskAbsenceScript = """
        ${'$'}ErrorActionPreference='Stop'
        ${'$'}ProgressPreference='SilentlyContinue'
        $taskMissingClassifierScript
        try {
            ${'$'}service=New-Object -ComObject 'Schedule.Service'
            ${'$'}service.Connect()
            ${'$'}folder=${'$'}service.GetFolder('\')
            try { ${'$'}task=${'$'}folder.GetTask('VPN Control'); [Console]::Out.Write('PRESENT') }
            catch { if (Test-MissingTask ${'$'}_.Exception) { [Console]::Out.Write('ABSENT') } else { [Console]::Out.Write('ERROR') } }
        } catch { [Console]::Out.Write('ERROR') }
    """.trimIndent()

    // Value names distinguish a missing Run registration from an empty REG_SZ and from value
    // kinds whose GetValue result is null. A present value is intentionally not inspected here.
    internal val runValueAbsenceScript = """
        ${'$'}ErrorActionPreference='Stop'
        ${'$'}ProgressPreference='SilentlyContinue'
        ${'$'}key=${'$'}null
        try {
            ${'$'}key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run',${'$'}false)
            if (${ '$' }null -eq ${ '$' }key) { [Console]::Out.Write('ABSENT') }
            else {
                ${'$'}present=${'$'}key.GetValueNames() | Where-Object { [string]::Equals(${ '$' }_, 'VPN Control', [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1
                if (${ '$' }null -eq ${ '$' }present) { [Console]::Out.Write('ABSENT') } else { [Console]::Out.Write('PRESENT') }
            }
        } catch { [Console]::Out.Write('ERROR') }
        finally { if (${ '$' }null -ne ${ '$' }key) { try { ${'$'}key.Dispose() } catch {} } }
    """.trimIndent()
}

internal fun currentAutostartPlatform(): DesktopAutostartPlatform {
    val osName = System.getProperty("os.name").lowercase(Locale.ROOT)
    return when {
        osName.contains("win") -> DesktopAutostartPlatform.WINDOWS
        osName.contains("linux") -> DesktopAutostartPlatform.LINUX
        else -> DesktopAutostartPlatform.UNSUPPORTED
    }
}
