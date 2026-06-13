package com.kardinal.vpncontrol.desktop

import java.nio.charset.StandardCharsets
import java.util.Base64

internal object DesktopCliProtocol {
    private const val COMMAND_PREFIX = "cli"
    private const val RESPONSE_PREFIX = "cli-response"
    private const val OK = "ok"
    private const val ERROR = "error"

    fun encodeCommand(command: DesktopCliCommand): String {
        return when (command) {
            DesktopCliCommand.On -> "$COMMAND_PREFIX\ton"
            DesktopCliCommand.Off -> "$COMMAND_PREFIX\toff"
            DesktopCliCommand.FindBest -> "$COMMAND_PREFIX\tfind-best"
            is DesktopCliCommand.Select -> "$COMMAND_PREFIX\tselect\t${encodeText(command.target)}"
        }
    }

    fun decodeCommand(line: String): Result<DesktopCliCommand> {
        return runCatching {
            val parts = line.split('\t')
            if (parts.firstOrNull() != COMMAND_PREFIX) {
                throw IllegalArgumentException("Unsupported activation command.")
            }
            when (parts.getOrNull(1)) {
                "on" -> DesktopCliCommand.On
                "off" -> DesktopCliCommand.Off
                "find-best" -> DesktopCliCommand.FindBest
                "select" -> {
                    val target = parts.getOrNull(2)?.let(::decodeText).orEmpty()
                    if (target.isBlank()) {
                        throw IllegalArgumentException("Missing location for select.")
                    }
                    DesktopCliCommand.Select(target)
                }
                else -> throw IllegalArgumentException("Unknown CLI activation command.")
            }
        }
    }

    fun encodeResponse(response: DesktopCliResponse): String {
        val status = if (response.success) OK else ERROR
        return "$RESPONSE_PREFIX\t$status\t${response.exitCode}\t${encodeText(response.message)}"
    }

    fun decodeResponse(line: String): DesktopCliResponse {
        return runCatching {
            val parts = line.split('\t')
            if (parts.firstOrNull() != RESPONSE_PREFIX) {
                return@runCatching invalidResponse()
            }
            val exitCode = parts.getOrNull(2)?.toIntOrNull() ?: 1
            val message = parts.getOrNull(3)?.let(::decodeText).orEmpty()
            when (parts.getOrNull(1)) {
                OK -> DesktopCliResponse.success(message)
                ERROR -> DesktopCliResponse.failure(message, exitCode = exitCode)
                else -> invalidResponse()
            }
        }.getOrElse { invalidResponse() }
    }

    private fun invalidResponse(): DesktopCliResponse =
        DesktopCliResponse.failure("Invalid response from VPN Control desktop app.", exitCode = 2)

    private fun encodeText(value: String): String {
        return Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(value.toByteArray(StandardCharsets.UTF_8))
    }

    private fun decodeText(value: String): String {
        return String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8)
    }
}
