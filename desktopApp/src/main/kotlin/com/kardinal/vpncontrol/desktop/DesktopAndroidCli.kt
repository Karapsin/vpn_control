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
               printError: (String) -> Unit,
               readInput: (String) -> Result<String> = ::readInput,
               readQrImage: (String) -> Result<String> = DesktopQrImage::read): Int {
        val requestId = UUID.randomUUID().toString()
        fun printResponse(response: DesktopCliResponse) {
            desktopCliRender(response, invocation.client.json, printLine, printError)
        }
        fun fail(code: ControlCode): Int {
            printResponse(desktopCliJsonFailure(code, requestId))
            return code.exitCode
        }
        if (invocation.flags.isNotEmpty() || invocation.operation in setOf(
                ControlOperationId.SERVE, ControlOperationId.GUI_SHOW, ControlOperationId.GUI_HIDE, ControlOperationId.QUIT)) {
            return fail(ControlCode.UNSUPPORTED)
        }
        val controlRequest = com.kardinal.vpncontrol.control.ControlCliRequestBuilder.build(
            invocation, requestId, readInput, readQrImage).getOrElse {
                return fail(if (it is OutOfMemoryError) ControlCode.UNAVAILABLE else ControlCode.INVALID_ARGUMENT)
            }
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
            val result = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(response.message)
            if (!result.ok) return rawFailure(result.code)
            val content = (result.data["content"] as? ControlValue.Text)?.value
            if (!result.final || result.code != ControlCode.OK || content == null) return rawFailure(ControlCode.INCOMPATIBLE_PROTOCOL)
            val code = DesktopControlExports.writeRaw(content, format, writeBinary)
            return if (code == ControlCode.OK) 0 else rawFailure(code)
        }
        // Preserve Android's explicit unavailable-revision/runtime warnings even without --json.
        printResponse(response)
        return response.exitCode
    }

    fun readInput(path: String): Result<String> = runCatching {
        val bytes = if (path == "-") System.`in`.readAllBytes()
            else Files.newInputStream(Path.of(path).toAbsolutePath()).use { it.readAllBytes() }
        try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } finally { bytes.fill(0) }
    }
}
