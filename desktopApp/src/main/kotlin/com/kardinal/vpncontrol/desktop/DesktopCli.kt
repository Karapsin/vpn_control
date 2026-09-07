package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue

internal sealed interface DesktopCliCommand {
    data class ControlServe(val requestId: String, val controllerId: String) : DesktopCliCommand
    data class ControlFrontendIdentityRead(val requestId: String, val frontendId: String) : DesktopCliCommand
    data class ControlFrontendLease(val requestId: String, val controllerId: String, val frontendId: String,
        val action: DesktopFrontendLeaseAction) : DesktopCliCommand
    data class ControlSnapshotRead(val controllerId: String? = null) : DesktopCliCommand
    data class ControlPresentationRead(val requestId: String, val controllerId: String? = null) : DesktopCliCommand
    data class ControlSubmit(
        val request: com.kardinal.vpncontrol.model.ControlRequest,
        val clientTimeoutSeconds: Long = 600,
    ) : DesktopCliCommand {
        init { require(clientTimeoutSeconds in 0..Long.MAX_VALUE / 1000) }
    }
    data object On : DesktopCliCommand
    data object Off : DesktopCliCommand
    data object Restart : DesktopCliCommand
    data object RoutingShow : DesktopCliCommand
    data object RoutingExport : DesktopCliCommand
    data class RoutingSet(val key: String, val value: String) : DesktopCliCommand {
        override fun toString(): String = "RoutingSet(<redacted>)"
    }
    data class RoutingImport(val content: String) : DesktopCliCommand {
        override fun toString(): String = "RoutingImport(<redacted>)"
    }
    data object Unsupported : DesktopCliCommand
    data object Languages : DesktopCliCommand
    data object SshKeyStatus : DesktopCliCommand
    data object Stats : DesktopCliCommand
    data object OperationsList : DesktopCliCommand
    data class OperationStatus(val id: String) : DesktopCliCommand
    data class OperationWait(val id: String) : DesktopCliCommand
    data class OperationCancel(val id: String) : DesktopCliCommand
    data object UpdatesStatus : DesktopCliCommand
    data object UpdatesCheck : DesktopCliCommand
    data object UpdatesDownload : DesktopCliCommand
    data object UpdatesDismiss : DesktopCliCommand
    data object DiagnosticsExport : DesktopCliCommand
    data class Logs(val limit: Int = 100) : DesktopCliCommand
    data class SshKeyImport(val content: String) : DesktopCliCommand {
        override fun toString(): String = "SshKeyImport(<redacted>)"
    }
    data object Status : DesktopCliCommand
    data object FindBest : DesktopCliCommand
    data class Select(val target: String) : DesktopCliCommand
    data object LocationsList : DesktopCliCommand
    data object LocationsExport : DesktopCliCommand
    data class LocationsImport(val content: String) : DesktopCliCommand {
        override fun toString(): String = "LocationsImport(<redacted>)"
    }
    data object SourceShow : DesktopCliCommand
    data object SubscriptionsList : DesktopCliCommand
    data class SubscriptionShow(val id: String) : DesktopCliCommand
    data class SubscriptionDelete(val id: String) : DesktopCliCommand
    data class SubscriptionRefresh(val target: String) : DesktopCliCommand
    data class LocationDelete(val target: String) : DesktopCliCommand
    data class LocationBenchmark(val target: String, val configurationId: String? = null) : DesktopCliCommand
    data class SubscriptionSave(val source: String?, val name: String?, val id: String? = null) : DesktopCliCommand {
        override fun toString(): String = "SubscriptionSave(<redacted>)"
    }
    data class SettingsShow(val key: String? = null) : DesktopCliCommand
    data class SettingsApply(val values: Map<String, com.kardinal.vpncontrol.model.ControlValue>) : DesktopCliCommand {
        override fun toString(): String = "SettingsApply(<redacted>)"
    }
    data class SourceSet(val subscriptionId: String?) : DesktopCliCommand
    data class LocationShow(val target: String) : DesktopCliCommand
    data class LocationSave(val content: String, val target: String? = null, val configurationId: String? = null) : DesktopCliCommand {
        override fun toString(): String = "LocationSave(<redacted>)"
    }
}

internal val DesktopCliCommand.isReadOnly: Boolean
    get() = this is DesktopCliCommand.ControlPresentationRead || this is DesktopCliCommand.ControlSnapshotRead || this == DesktopCliCommand.Status || this == DesktopCliCommand.LocationsList || this == DesktopCliCommand.LocationsExport ||
        this == DesktopCliCommand.SourceShow || this is DesktopCliCommand.LocationShow || this is DesktopCliCommand.SettingsShow ||
        this == DesktopCliCommand.SubscriptionsList || this is DesktopCliCommand.SubscriptionShow ||
        this == DesktopCliCommand.RoutingShow || this == DesktopCliCommand.RoutingExport || this == DesktopCliCommand.Unsupported ||
        this == DesktopCliCommand.Languages || this == DesktopCliCommand.SshKeyStatus ||
        this == DesktopCliCommand.Stats || this == DesktopCliCommand.OperationsList || this is DesktopCliCommand.OperationStatus || this is DesktopCliCommand.OperationWait ||
        this == DesktopCliCommand.UpdatesStatus || this == DesktopCliCommand.DiagnosticsExport || this is DesktopCliCommand.Logs

/** Cancellation changes operation state but must remain available during a configuration mutation. */
internal val DesktopCliCommand.bypassesMutationAdmission: Boolean
    get() = isReadOnly || this is DesktopCliCommand.OperationCancel || this is DesktopCliCommand.ControlSubmit ||
        this is DesktopCliCommand.ControlFrontendLease || this is DesktopCliCommand.ControlFrontendIdentityRead || this is DesktopCliCommand.ControlServe

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
    fun handleArgs(
        args: Array<String>,
        printLine: (String) -> Unit = ::desktopCliPrintLine,
        requestCommand: (DesktopCliCommand) -> DesktopCliResponse = DesktopPublicCliClient::request,
        startHeadlessController: (DesktopCliCommand) -> DesktopCliResponse = DesktopPublicCliClient::start,
        readInput: (String) -> Result<String> = DesktopAndroidCli::readInput,
        writeOutput: (String, String) -> Result<Unit> = DesktopPrivateExportWriter::writeText,
        readQrImage: (String) -> Result<String> = DesktopQrImage::read,
        writeBinaryOutput: (String, ByteArray) -> Result<Unit> = { path, content -> runCatching {
            if (path == "-") {
                System.out.write(content)
                System.out.flush()
                check(!System.out.checkError())
            } else DesktopPrivateExportWriter.write(path, content).getOrThrow()
            Unit
        } },
        androidRequest: (com.kardinal.vpncontrol.model.ControlRequest, String?, Long) -> DesktopCliResponse =
            DesktopAndroidAdbClient()::request,
        printProgress: (String) -> Unit = { writeDesktopCliLine(System.err, it) },
        streamPause: () -> Unit = { Thread.sleep(250) },
        streamActive: () -> Boolean = { !Thread.currentThread().isInterrupted },
    ): Int? {
        val requestId = java.util.UUID.randomUUID().toString()
        fun fail(code: ControlCode) = desktopCliRender(desktopCliJsonFailure(code, requestId),
            desktopCliWantsJson(args.toList()), printLine, printProgress)
        val invocation = when (val parsed = ControlCliParser.parse(args.toList())) {
            is ControlCliParseResult.Gui -> return null
            is ControlCliParseResult.Help -> {
                printLine(com.kardinal.vpncontrol.control.ControlCliHelp.render("vpn-control", parsed.operation))
                return 0
            }
            is ControlCliParseResult.Version -> { printLine(DesktopBuildInfo.current().displayVersion); return 0 }
            is ControlCliParseResult.Invalid -> return fail(ControlCode.INVALID_ARGUMENT)
            is ControlCliParseResult.Invocation -> parsed
        }
        if (invocation.flags.isNotEmpty()) {
            return DesktopCliStream.run(invocation, { request, timeout ->
                if (invocation.client.android) androidRequest(request, invocation.client.serial, timeout)
                else requestCommand(DesktopCliCommand.ControlSubmit(request, timeout))
            }, printLine, printProgress, streamPause, streamActive)
        }
        if (invocation.client.android) return DesktopAndroidCli.handle(invocation, printLine, androidRequest,
            writeOutput, writeBinaryOutput, printProgress, readInput, readQrImage)
        if (invocation.operation == ControlOperationId.CAPABILITIES) {
            if (invocation.client.copy(json = false, timeoutSeconds = 600, stateDirectory = null) !=
                com.kardinal.vpncontrol.control.ControlClientOptions()) return fail(ControlCode.UNSUPPORTED)
            val platform = currentDesktopControlPlatform() ?: return fail(ControlCode.UNSUPPORTED)
            val result = com.kardinal.vpncontrol.model.ControlResult(null, requestId, ControlCode.OK, 0,
                data = DesktopControlSupport.describe(platform),
                warnings = listOf("OWNER_METADATA_UNAVAILABLE", "RUNTIME_READINESS_NOT_CHECKED"))
            return desktopCliRender(DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result)),
                invocation.client.json, printLine, printProgress)
        }
        if (invocation.client.interactive || invocation.operation !in DesktopControlSupport.jsonOperations ||
            invocation.client.asynchronous && invocation.operation !in DesktopControlSupport.asynchronousOperations ||
            invocation.client.ifRevision != null && invocation.operation !in DesktopControlSupport.revisionGuardOperations)
            return fail(ControlCode.UNSUPPORTED)
        val request = com.kardinal.vpncontrol.control.ControlCliRequestBuilder.build(invocation, requestId, readInput, readQrImage)
            .getOrElse { return fail(if (it is OutOfMemoryError) ControlCode.UNAVAILABLE else ControlCode.INVALID_ARGUMENT) }
        if (request.command.operation in DesktopControlMutations.operations && DesktopControlMutations.command(request.command) == null)
            return fail(ControlCode.INVALID_ARGUMENT)
        val submit = DesktopCliCommand.ControlSubmit(request, invocation.client.timeoutSeconds)
        val first = requestCommand(submit)
        val response = if (first.isDesktopAppNotRunning && request.controllerId == null &&
            request.command.operation !in noStartupOperations) startHeadlessController(submit) else first
        val formatted = desktopCliJsonResponse(request, response)
        if (request.command.operation in DesktopControlExports.operations) {
            val output = requireNotNull(invocation.options["--output"])
            val format = invocation.options["--format"] ?: if (request.command.operation == ControlOperationId.DIAGNOSTICS_EXPORT) "text" else "json"
            if (output == "-") {
                val result = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(formatted.message)
                val content = (result.data["content"] as? ControlValue.Text)?.value
                val code = if (!result.ok) result.code else if (!result.final || result.code != ControlCode.OK || content == null)
                    ControlCode.INCOMPATIBLE_PROTOCOL else DesktopControlExports.writeRaw(content, format, writeBinaryOutput)
                if (code != ControlCode.OK) printProgress(code.wireName)
                return code.exitCode
            }
            return desktopCliRender(DesktopControlExports.write(formatted, output, format, writeOutput, writeBinaryOutput),
                invocation.client.json, printLine, printProgress)
        }
        return desktopCliRender(formatted, invocation.client.json, printLine, printProgress)
    }

    private val noStartupOperations = setOf(ControlOperationId.STATUS, ControlOperationId.GUI_HIDE, ControlOperationId.QUIT,
        ControlOperationId.OPERATIONS_LIST, ControlOperationId.OPERATIONS_STATUS, ControlOperationId.OPERATIONS_WAIT,
        ControlOperationId.OPERATIONS_CANCEL)
}
