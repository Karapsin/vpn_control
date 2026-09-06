package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.model.*
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID

internal object DesktopAndroidCli {
    fun handle(invocation: ControlCliParseResult.Invocation, printLine: (String) -> Unit,
               request: (ControlRequest, String?, Long) -> DesktopCliResponse,
               writeText: (String, String) -> Result<Unit>,
               writeBinary: (String, ByteArray) -> Result<Unit>,
               printError: (String) -> Unit): Int {
        val requestId = UUID.randomUUID().toString()
        fun printResponse(response: DesktopCliResponse) {
            printLine(if (invocation.client.json) response.message else desktopAndroidHumanOutput(
                com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)))
        }
        fun fail(code: ControlCode): Int {
            printResponse(desktopCliJsonFailure(code, requestId))
            return code.exitCode
        }
        if (invocation.flags.isNotEmpty() || invocation.operation in setOf(
                ControlOperationId.SERVE, ControlOperationId.GUI_SHOW, ControlOperationId.GUI_HIDE, ControlOperationId.QUIT)) {
            return fail(ControlCode.UNSUPPORTED)
        }
        val names = ControlCliParser.schema(invocation.operation).positional
        val arguments = invocation.positional.mapIndexed { index, value -> names[index] to ControlValue.Text(value) }.toMap() +
            invocation.options.filterKeys { it !in setOf("--output", "--format") }.map { (option, value) ->
                val content = when (option) {
                    "--input" -> readInput(value).getOrNull()
                    "--qr-image" -> DesktopQrImage.read(value).getOrNull()
                    else -> value
                } ?: return fail(ControlCode.INVALID_ARGUMENT)
                (if (option == "--qr-image") "input" else option.removePrefix("--")) to ControlValue.Text(content)
            }.toMap()
        val controlRequest = ControlRequest(requestId, ControlCommand(invocation.operation, arguments),
            interactive = invocation.client.interactive, asynchronous = invocation.client.asynchronous,
            controllerId = invocation.client.controllerId, ifRevision = invocation.client.ifRevision)
        val response = desktopCliJsonResponse(controlRequest,
            request(controlRequest, invocation.client.serial, invocation.client.timeoutSeconds))
        if (invocation.operation in DesktopControlExports.operations) {
            val output = requireNotNull(invocation.options["--output"])
            val format = invocation.options["--format"] ?: "json"
            if (output != "-") {
                val exported = DesktopControlExports.write(response, output, format, writeText, writeBinary)
                printResponse(exported)
                return exported.exitCode
            }
            // Raw stdout cannot share an envelope or an appended success line.
            fun rawFailure(code: ControlCode): Int { printError(code.wireName); return code.exitCode }
            if (invocation.client.json) return fail(ControlCode.INVALID_ARGUMENT)
            val result = com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
            if (!result.ok) return rawFailure(result.code)
            val content = (result.data["content"] as? ControlValue.Text)?.value
            if (!result.final || result.code != ControlCode.OK || content == null) return rawFailure(ControlCode.INCOMPATIBLE_PROTOCOL)
            val bytes = if (format == "qr-png") DesktopQrImage.encode(content).getOrNull()
                ?: return rawFailure(ControlCode.INVALID_ARGUMENT) else content.toByteArray(Charsets.UTF_8)
            return if (runCatching { writeBinary(output, bytes).getOrThrow() }.isSuccess) 0 else rawFailure(ControlCode.PERSISTENCE_FAILED)
        }
        // Preserve Android's explicit unavailable-revision/runtime warnings even without --json.
        printResponse(response)
        return response.exitCode
    }

    private fun readInput(path: String): Result<String> = runCatching {
        val bytes = if (path == "-") System.`in`.readNBytes(1_048_577)
            else Files.newInputStream(Path.of(path).toAbsolutePath()).use { it.readNBytes(1_048_577) }
        try {
            require(bytes.size <= 1_048_576)
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } finally { bytes.fill(0) }
    }
}
