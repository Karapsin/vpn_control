package com.kardinal.vpncontrol.desktop

import java.util.concurrent.TimeUnit

internal object DesktopWindowsElevation {
    const val ELEVATION_ATTEMPTED_ARG = "--elevation-attempted"

    fun elevateIfRequired(
        args: Array<String>,
        osName: String = System.getProperty("os.name"),
        currentCommand: String? = ProcessHandle.current().info().command().orElse(null),
        isAdministrator: () -> Boolean = ::hasAdministratorPrivileges,
        launchElevated: (String, List<String>) -> Boolean = ::launchElevated,
        printLine: (String) -> Unit = ::println,
    ): Int? {
        if (!osName.contains("windows", ignoreCase = true)) {
            return null
        }
        if (isAdministrator()) {
            return null
        }
        if (args.contains(ELEVATION_ATTEMPTED_ARG)) {
            printLine("VPN Control requires Administrator privileges on Windows.")
            return 1
        }

        val command = currentCommand?.takeIf(String::isNotBlank)
        if (command == null) {
            printLine("VPN Control could not determine its launcher path for Windows elevation.")
            return 1
        }

        val elevatedArgs = args.toList() + ELEVATION_ATTEMPTED_ARG
        return if (launchElevated(command, elevatedArgs)) {
            0
        } else {
            printLine("VPN Control elevation was cancelled or failed.")
            1
        }
    }

    private fun hasAdministratorPrivileges(): Boolean {
        val principalCheck = runCommand(
            command = listOf(
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ),
            timeoutSeconds = 3,
        )
        if (principalCheck.exitCode == 0 && principalCheck.output.trim().equals("true", ignoreCase = true)) {
            return true
        }

        val netSessionCheck = runCommand(
            command = listOf("cmd.exe", "/c", "net session >nul 2>nul"),
            timeoutSeconds = 3,
        )
        return netSessionCheck.exitCode == 0
    }

    private fun launchElevated(command: String, args: List<String>): Boolean {
        val script = buildString {
            append("Start-Process -FilePath ")
            append(command.asPowerShellLiteral())
            if (args.isNotEmpty()) {
                append(" -ArgumentList @(")
                append(args.joinToString(",") { it.asPowerShellLiteral() })
                append(")")
            }
            append(" -Verb RunAs")
        }
        val result = runCommand(
            command = listOf(
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ),
            timeoutSeconds = 15,
        )
        return result.exitCode == 0
    }

    private fun runCommand(command: List<String>, timeoutSeconds: Long): CommandResult {
        return runCatching {
            val process = ProcessBuilder(command)
                .redirectErrorStream(true)
                .start()
            val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            if (!completed) {
                process.destroyForcibly()
                return CommandResult(exitCode = -1, output = "")
            }
            CommandResult(
                exitCode = process.exitValue(),
                output = process.inputStream.bufferedReader().use { it.readText() },
            )
        }.getOrElse {
            CommandResult(exitCode = -1, output = it.message.orEmpty())
        }
    }

    private fun String.asPowerShellLiteral(): String {
        return "'${replace("'", "''")}'"
    }

    private data class CommandResult(
        val exitCode: Int,
        val output: String,
    )
}
