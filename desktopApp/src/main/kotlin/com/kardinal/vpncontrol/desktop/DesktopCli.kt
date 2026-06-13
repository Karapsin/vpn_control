package com.kardinal.vpncontrol.desktop

internal sealed interface DesktopCliCommand {
    data object On : DesktopCliCommand
    data object Off : DesktopCliCommand
    data object FindBest : DesktopCliCommand
    data class Select(val target: String) : DesktopCliCommand
}

internal data class DesktopCliResponse(
    val success: Boolean,
    val message: String,
    val exitCode: Int = if (success) 0 else 1,
) {
    val isDesktopAppNotRunning: Boolean
        get() = !success && exitCode == UNAVAILABLE_EXIT_CODE && message == NOT_RUNNING_MESSAGE

    companion object {
        const val UNAVAILABLE_EXIT_CODE = 2
        const val NOT_RUNNING_MESSAGE = "VPN Control desktop app is not running."

        fun success(message: String): DesktopCliResponse =
            DesktopCliResponse(success = true, message = message, exitCode = 0)

        fun failure(message: String, exitCode: Int = 1): DesktopCliResponse =
            DesktopCliResponse(success = false, message = message, exitCode = exitCode)

        fun notRunning(): DesktopCliResponse =
            failure(NOT_RUNNING_MESSAGE, exitCode = UNAVAILABLE_EXIT_CODE)
    }
}

internal object DesktopCli {
    private val usage = """
        Usage:
          vpn-control on
          vpn-control off
          vpn-control find-best
          vpn-control select <location-name|visible-index>
    """.trimIndent()

    fun handleArgs(
        args: Array<String>,
        printLine: (String) -> Unit = ::println,
        requestCommand: (DesktopCliCommand) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
        startHeadlessController: (DesktopCliCommand) -> DesktopCliResponse = DesktopHeadlessController::startForCliCommand,
    ): Int? {
        return when (val parsed = parse(args.toList()) ?: return null) {
            is DesktopCliParseResult.Valid -> {
                val firstResponse = requestCommand(parsed.command)
                val response = if (firstResponse.isDesktopAppNotRunning) {
                    startHeadlessController(parsed.command)
                } else {
                    firstResponse
                }
                printLine(response.message)
                response.exitCode
            }
            is DesktopCliParseResult.Invalid -> {
                printLine(parsed.message)
                printLine(usage)
                1
            }
        }
    }

    private fun parse(args: List<String>): DesktopCliParseResult? {
        val command = args.firstOrNull() ?: return null
        if (command.startsWith("--")) return null
        return when (command) {
            "on" -> noExtraArgs(args, DesktopCliCommand.On)
            "off" -> noExtraArgs(args, DesktopCliCommand.Off)
            "find-best" -> noExtraArgs(args, DesktopCliCommand.FindBest)
            "select" -> {
                val target = args.drop(1).joinToString(" ").trim()
                if (target.isBlank()) {
                    DesktopCliParseResult.Invalid("Missing location for select.")
                } else {
                    DesktopCliParseResult.Valid(DesktopCliCommand.Select(target))
                }
            }
            else -> DesktopCliParseResult.Invalid("Unknown command: $command")
        }
    }

    private fun noExtraArgs(args: List<String>, command: DesktopCliCommand): DesktopCliParseResult {
        return if (args.size == 1) {
            DesktopCliParseResult.Valid(command)
        } else {
            DesktopCliParseResult.Invalid("Unexpected arguments for ${args.first()}.")
        }
    }
}

private sealed interface DesktopCliParseResult {
    data class Valid(val command: DesktopCliCommand) : DesktopCliParseResult
    data class Invalid(val message: String) : DesktopCliParseResult
}
