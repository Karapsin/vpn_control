package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.control.ControlCliParser
import java.nio.file.Files
import java.nio.file.Path

internal data class DesktopWorkspaceInvocation(val arguments: List<String>, val directory: Path?)

internal object DesktopWorkspacePaths {
    @Volatile private var selected: Path? = null
    fun root(): Path = selected ?: Path.of(System.getProperty("user.home"), ".vpn-control-desktop")
    fun overrideDirectory(): Path? = selected
    fun configure(invocation: DesktopWorkspaceInvocation) { selected = invocation.directory }

    /** Read-only resolution coalesces symlink aliases even when the final directory does not exist. */
    fun resolve(raw: String, workingDirectory: Path = Path.of("").toAbsolutePath()): Path {
        require(raw.isNotBlank())
        val target = workingDirectory.resolve(raw).toAbsolutePath().normalize()
        var ancestor = target
        while (!Files.exists(ancestor)) ancestor = requireNotNull(ancestor.parent)
        require(Files.isDirectory(ancestor))
        return ancestor.toRealPath().resolve(ancestor.relativize(target)).normalize()
    }

    fun parse(arguments: List<String>, workingDirectory: Path = Path.of("").toAbsolutePath()): Result<DesktopWorkspaceInvocation> = runCatching {
        val literalIndex = arguments.indexOf("--").takeIf { it >= 0 } ?: arguments.size
        val indices = arguments.indices.filter { it < literalIndex && arguments[it] == "--state-dir" }
        if (indices.isEmpty()) return@runCatching DesktopWorkspaceInvocation(arguments, null)
        require(indices.size == 1)
        val index = indices.single()
        val raw = requireNotNull(arguments.getOrNull(index + 1))
        require(raw.isNotBlank() && !raw.startsWith("--"))
        val remaining = arguments.filterIndexed { i, _ -> i != index && i != index + 1 }
        val internalOwner = remaining == listOf(DesktopHeadlessController.ARG)
        val internalFrontend = remaining.size == 2 && remaining[0] == DESKTOP_FRONTEND_OWNER_ARGUMENT &&
            runCatching { java.util.UUID.fromString(remaining[1]).toString() == remaining[1] }.getOrDefault(false)
        val gui = remaining.all { it in setOf("--autostart", "--tray", "--minimized") }
        if (!internalOwner && !internalFrontend && !gui) {
            val parsed = ControlCliParser.parse(arguments)
            if (parsed is ControlCliParseResult.Help || parsed is ControlCliParseResult.Version)
                return@runCatching DesktopWorkspaceInvocation(remaining, null)
            require(parsed is ControlCliParseResult.Invocation && !parsed.client.android)
        }
        DesktopWorkspaceInvocation(remaining, resolve(raw, workingDirectory))
    }
}
