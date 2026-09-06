package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.model.ControlOperationId

internal sealed interface DesktopCliCommand {
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
        this is DesktopCliCommand.ControlFrontendLease || this is DesktopCliCommand.ControlFrontendIdentityRead

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
          vpn-control [--state-dir <path>] <command>
          vpn-control on
          vpn-control off
          vpn-control restart
          vpn-control status [--watch] [--json]
          vpn-control capabilities [--json]
          vpn-control --android [--serial SERIAL] <command> [--json]
          vpn-control find-best
          vpn-control operations list
          vpn-control operations status <id>
          vpn-control operations wait <id>
          vpn-control operations cancel <id>
          vpn-control --async <find-best|locations benchmark ...|subscriptions refresh ...|updates check|updates download>
          vpn-control select <location-name|visible-index>
          vpn-control locations list
          vpn-control locations import --input <path|->
          vpn-control locations import --qr-image <path>
          vpn-control locations export --output <path|-> [--format json|qr-png]
          vpn-control source show
          vpn-control source set <current-locations|subscription ID|all>
          vpn-control locations show <location-name|visible-index>
          vpn-control locations add --input <path|->
          vpn-control locations add --qr-image <path>
          vpn-control locations update <location-name|visible-index> --input <path|->
          vpn-control settings show [key] [--json]
          vpn-control settings set <key> <value> [--json]
          vpn-control settings apply --input <path|-> [--json]
          vpn-control --controller-id <observed-owner> --if-revision <revision> settings set <key> <value>
          vpn-control settings languages
          vpn-control ssh key status
          vpn-control ssh key import --input <path|->
          vpn-control stats [--watch] [--json]
          vpn-control logs [--follow] [--limit <count>] [--json]
          vpn-control diagnostics export --output <path|->
          vpn-control updates <status|check|download|dismiss>
          vpn-control routing show
          vpn-control routing set <ignore-rules|block-quic-udp443|direct-domains> <value>
          vpn-control routing import --input <path|->
          vpn-control routing import --qr-image <path>
          vpn-control routing export --output <path|-> [--format json|qr-png]
          vpn-control subscriptions list
          vpn-control subscriptions show <id>
          vpn-control subscriptions delete <id>
          vpn-control subscriptions refresh <id|active|all>
          vpn-control locations delete <location-name|visible-index>
          vpn-control locations benchmark <location-name|visible-index>
          vpn-control subscriptions add --input <path|-> [--name <name>]
          vpn-control subscriptions add --qr-image <path> [--name <name>]
          vpn-control subscriptions update <id> [--input <path|->] [--name <name>]
    """.trimIndent()

    fun handleArgs(
        args: Array<String>,
        printLine: (String) -> Unit = ::desktopCliPrintLine,
        requestCommand: (DesktopCliCommand) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
        startHeadlessController: (DesktopCliCommand) -> DesktopCliResponse = DesktopHeadlessController::startForCliCommand,
        readInput: (String) -> Result<String> = { path -> runCatching {
            if (path == "-") System.`in`.bufferedReader(Charsets.UTF_8).readText()
            else java.nio.file.Files.readString(java.nio.file.Path.of(path).toAbsolutePath())
        } },
        writeOutput: (String, String) -> Result<Unit> = { path, content ->
            DesktopPrivateExportWriter.write(path, content.toByteArray(Charsets.UTF_8))
        },
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
        if (args.toList() == listOf("--help") || args.toList() == listOf("help")) {
            printLine(usage)
            return 0
        }
        if (args.toList() == listOf("--version")) {
            printLine(DesktopBuildInfo.current().displayVersion)
            return 0
        }
        val capabilityInvocation = ControlCliParser.parse(args.toList())
        if (capabilityInvocation is ControlCliParseResult.Help) { printLine(usage); return 0 }
        if (capabilityInvocation is ControlCliParseResult.Version) { printLine(DesktopBuildInfo.current().displayVersion); return 0 }
        if (capabilityInvocation is ControlCliParseResult.Invocation && capabilityInvocation.client.android) {
            return DesktopAndroidCli.handle(capabilityInvocation, printLine, androidRequest, writeOutput, writeBinaryOutput, printProgress)
        }
        if (capabilityInvocation is ControlCliParseResult.Invocation && capabilityInvocation.flags.isNotEmpty()) {
            return DesktopCliStream.run(capabilityInvocation, requestCommand, printLine, printProgress, streamPause, streamActive)
        }
        if (capabilityInvocation is ControlCliParseResult.Invocation && capabilityInvocation.operation == ControlOperationId.CAPABILITIES &&
            capabilityInvocation.client.copy(json = false, timeoutSeconds = 600) == com.kardinal.vpncontrol.control.ControlClientOptions()) {
            val platform = currentDesktopControlPlatform()
            val requestId = java.util.UUID.randomUUID().toString()
            if (platform == null) {
                printLine(if (capabilityInvocation.client.json) desktopCliJsonFailure(
                    com.kardinal.vpncontrol.model.ControlCode.UNSUPPORTED, requestId).message else "UNSUPPORTED")
                return 1
            }
            val data = DesktopControlSupport.describe(platform)
            if (capabilityInvocation.client.json) printLine(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(
                com.kardinal.vpncontrol.model.ControlResult(null, requestId, com.kardinal.vpncontrol.model.ControlCode.OK, 0,
                    data = data, warnings = listOf("OWNER_METADATA_UNAVAILABLE", "RUNTIME_READINESS_NOT_CHECKED"))))
            else printLine(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(data))
            return 0
        }
        return when (val parsed = parse(args.toList(), readInput, readQrImage) ?: return null) {
            is DesktopCliParseResult.Valid -> {
                if (parsed.command == DesktopCliCommand.Unsupported) {
                    printLine("UNSUPPORTED")
                    return 1
                }
                val firstResponse = requestCommand(parsed.command)
                val response = if (
                    firstResponse.isDesktopAppNotRunning &&
                        (parsed.command as? DesktopCliCommand.ControlSubmit)?.request?.controllerId == null &&
                        parsed.command != DesktopCliCommand.Status &&
                        parsed.command != DesktopCliCommand.OperationsList && parsed.command !is DesktopCliCommand.OperationStatus &&
                        parsed.command !is DesktopCliCommand.OperationWait && parsed.command !is DesktopCliCommand.OperationCancel &&
                        (parsed.command as? DesktopCliCommand.ControlSubmit)?.request?.command?.operation !in setOf(
                            ControlOperationId.STATUS, ControlOperationId.GUI_HIDE, ControlOperationId.QUIT, ControlOperationId.OPERATIONS_LIST, ControlOperationId.OPERATIONS_STATUS,
                            ControlOperationId.OPERATIONS_WAIT, ControlOperationId.OPERATIONS_CANCEL)
                ) {
                    startHeadlessController(parsed.command)
                } else {
                    firstResponse
                }
                if (parsed.json) {
                    val formatted = desktopCliJsonResponse((parsed.command as DesktopCliCommand.ControlSubmit).request, response)
                    if (parsed.command.request.command.operation in DesktopControlExports.operations && parsed.output != null) {
                        val exported = DesktopControlExports.write(formatted, parsed.output, parsed.format, writeOutput, writeBinaryOutput)
                        printLine(exported.message)
                        return exported.exitCode
                    }
                    printLine(formatted.message)
                    return formatted.exitCode
                }
                if (response.success && parsed.output != null && parsed.format == "qr-png") {
                    val encoded = DesktopQrImage.encode(response.message)
                    if (encoded.isFailure) {
                        printLine(encoded.exceptionOrNull()?.message ?: "INVALID_ARGUMENT")
                        return 1
                    }
                    if (writeBinaryOutput(parsed.output, encoded.getOrThrow()).isFailure) {
                        printLine("Could not write export output (destination must not already exist).")
                        return 1
                    }
                    if (parsed.output != "-") printLine("Exported.")
                } else if (response.success && parsed.output != null && parsed.output != "-") {
                    if (writeOutput(parsed.output, response.message).isFailure) {
                        printLine("Could not write export output (destination must not already exist).")
                        return 1
                    }
                    printLine("Exported.")
                } else if (parsed.command is DesktopCliCommand.ControlSubmit && parsed.command.request.controllerId != null) {
                    val formatted = desktopCliJsonResponse(parsed.command.request, response)
                    val result = com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(formatted.message)
                    printLine(if (parsed.command.request.command.operation in DesktopControlSupport.revisionGuardOperations || !result.ok)
                        result.code.wireName else formatted.message)
                    return formatted.exitCode
                } else if (parsed.command is DesktopCliCommand.ControlSubmit &&
                    parsed.command.request.command.operation in setOf(ControlOperationId.UPDATES_CANCEL, ControlOperationId.QUIT, ControlOperationId.GUI_SHOW, ControlOperationId.GUI_HIDE)) {
                    val result = runCatching { com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message) }.getOrNull()
                    printLine(result?.code?.wireName ?: response.message)
                } else printLine(response.message)
                response.exitCode
            }
            is DesktopCliParseResult.Invalid -> {
                if (desktopCliWantsJson(args.toList())) {
                    val failure = desktopCliJsonFailure(com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT,
                        java.util.UUID.randomUUID().toString())
                    printLine(failure.message)
                    return failure.exitCode
                }
                printLine(parsed.message)
                printLine(usage)
                1
            }
        }
    }

    private fun parse(args: List<String>, readInput: (String) -> Result<String>,
                      readQrImage: (String) -> Result<String>): DesktopCliParseResult? {
        val sharedInvocation = ControlCliParser.parse(args)
        if (sharedInvocation is ControlCliParseResult.Invocation && (sharedInvocation.client.json || sharedInvocation.client.asynchronous || sharedInvocation.client.controllerId != null || sharedInvocation.operation in DesktopGuiVisibilityControl.operations)) {
            if (sharedInvocation.client.copy(json = false, asynchronous = false, timeoutSeconds = 600, controllerId = null, ifRevision = null) != com.kardinal.vpncontrol.control.ControlClientOptions() ||
                sharedInvocation.flags.isNotEmpty() || sharedInvocation.operation !in DesktopControlSupport.jsonOperations)
                return DesktopCliParseResult.Invalid("Unsupported JSON control options.")
            if (sharedInvocation.client.asynchronous && sharedInvocation.operation !in DesktopControlSupport.asynchronousOperations)
                return DesktopCliParseResult.Invalid("This operation does not support asynchronous submission.")
            if (sharedInvocation.client.ifRevision != null && sharedInvocation.operation !in DesktopControlSupport.revisionGuardOperations)
                return DesktopCliParseResult.Invalid("This operation does not support revision guards.")
            val names = ControlCliParser.schema(sharedInvocation.operation).positional
            val arguments = sharedInvocation.positional.mapIndexed { index, value ->
                names[index] to com.kardinal.vpncontrol.model.ControlValue.Text(value)
            }.toMap() + sharedInvocation.options.filterKeys { it !in setOf("--output", "--format") }.map { (option, value) ->
                val content = when (option) {
                    "--input" -> readInput(value).getOrNull()
                    "--qr-image" -> readQrImage(value).getOrNull()
                    else -> value
                } ?: return DesktopCliParseResult.Invalid("Could not read command input.")
                (if (option == "--qr-image") "input" else option.removePrefix("--")) to com.kardinal.vpncontrol.model.ControlValue.Text(content)
            }.toMap()
            if (sharedInvocation.operation in DesktopControlMutations.operations && DesktopControlMutations.command(
                    com.kardinal.vpncontrol.model.ControlCommand(sharedInvocation.operation, arguments)) == null) {
                return DesktopCliParseResult.Invalid("Invalid command arguments.")
            }
            if (sharedInvocation.operation in setOf(ControlOperationId.SETTINGS_SET, ControlOperationId.SETTINGS_APPLY) &&
                com.kardinal.vpncontrol.control.ControlSettingsLogic.parseRequestArguments(
                    sharedInvocation.operation, arguments).isFailure)
                return DesktopCliParseResult.Invalid("Invalid settings input.")
            return DesktopCliParseResult.Valid(DesktopCliCommand.ControlSubmit(com.kardinal.vpncontrol.model.ControlRequest(
                requestId = java.util.UUID.randomUUID().toString(),
                command = com.kardinal.vpncontrol.model.ControlCommand(sharedInvocation.operation, arguments),
                asynchronous = sharedInvocation.client.asynchronous, controllerId = sharedInvocation.client.controllerId,
                ifRevision = sharedInvocation.client.ifRevision), sharedInvocation.client.timeoutSeconds),
                output = sharedInvocation.options["--output"], json = sharedInvocation.client.json,
                format = sharedInvocation.options["--format"] ?: if (sharedInvocation.operation == ControlOperationId.DIAGNOSTICS_EXPORT) "text" else "json")
        }
        val command = args.firstOrNull() ?: return null
        if (args.all { it in setOf("--tray", "--autostart", "--minimized") }) return null
        if (command.startsWith("--")) return DesktopCliParseResult.Invalid("Unknown or unsupported command option.")
        if (command in setOf("locations", "source", "settings", "subscriptions", "routing", "ssh", "stats", "logs", "diagnostics", "updates", "operations")) {
            val parsed = ControlCliParser.parse(args)
            if (parsed !is ControlCliParseResult.Invocation) return DesktopCliParseResult.Invalid("Invalid location command arguments.")
            if (parsed.client != com.kardinal.vpncontrol.control.ControlClientOptions() || parsed.flags.isNotEmpty()) {
                return DesktopCliParseResult.Invalid("Global control options require the shared controller interface.")
            }
            val result = when (parsed.operation) {
                ControlOperationId.UPDATES_CANCEL -> DesktopCliCommand.ControlSubmit(com.kardinal.vpncontrol.model.ControlRequest(
                    java.util.UUID.randomUUID().toString(), com.kardinal.vpncontrol.model.ControlCommand(ControlOperationId.UPDATES_CANCEL)))
                ControlOperationId.OPERATIONS_LIST -> DesktopCliCommand.OperationsList
                ControlOperationId.OPERATIONS_STATUS -> DesktopCliCommand.OperationStatus(parsed.positional.single())
                ControlOperationId.OPERATIONS_WAIT -> DesktopCliCommand.OperationWait(parsed.positional.single())
                ControlOperationId.OPERATIONS_CANCEL -> DesktopCliCommand.OperationCancel(parsed.positional.single())
                ControlOperationId.STATS -> DesktopCliCommand.Stats
                ControlOperationId.LOGS -> DesktopCliCommand.Logs(parsed.options["--limit"]?.toInt() ?: 100)
                ControlOperationId.DIAGNOSTICS_EXPORT -> DesktopCliCommand.DiagnosticsExport
                ControlOperationId.LOCATIONS_IMPORT -> {
                    DesktopCliCommand.LocationsImport(readTransferInput(parsed.options, readInput, readQrImage)
                        ?: return DesktopCliParseResult.Invalid("Could not read location input."))
                }
                ControlOperationId.LOCATIONS_EXPORT -> DesktopCliCommand.LocationsExport
                ControlOperationId.SETTINGS_LANGUAGES -> DesktopCliCommand.Languages
                ControlOperationId.SSH_KEY_STATUS -> DesktopCliCommand.SshKeyStatus
                ControlOperationId.SSH_KEY_IMPORT -> DesktopCliCommand.SshKeyImport(
                    readInput(parsed.options.getValue("--input")).getOrNull()
                        ?: return DesktopCliParseResult.Invalid("Could not read private key input."))
                ControlOperationId.ROUTING_SHOW -> DesktopCliCommand.RoutingShow
                ControlOperationId.ROUTING_EXPORT -> DesktopCliCommand.RoutingExport
                ControlOperationId.ROUTING_SET -> DesktopCliCommand.RoutingSet(parsed.positional[0], parsed.positional[1])
                ControlOperationId.ROUTING_IMPORT -> {
                    DesktopCliCommand.RoutingImport(readTransferInput(parsed.options, readInput, readQrImage)
                        ?: return DesktopCliParseResult.Invalid("Could not read routing input."))
                }
                ControlOperationId.ROUTING_APPS_LIST, ControlOperationId.ROUTING_APPS_SET,
                ControlOperationId.ROUTING_APPS_ADD, ControlOperationId.ROUTING_APPS_REMOVE,
                ControlOperationId.ROUTING_APPS_CLEAR, ControlOperationId.ROUTING_APPS_SELECT_ALL -> DesktopCliCommand.Unsupported
                ControlOperationId.SUBSCRIPTIONS_LIST -> DesktopCliCommand.SubscriptionsList
                ControlOperationId.SUBSCRIPTIONS_SHOW -> DesktopCliCommand.SubscriptionShow(parsed.positional.single())
                ControlOperationId.SUBSCRIPTIONS_DELETE -> DesktopCliCommand.SubscriptionDelete(parsed.positional.single())
                ControlOperationId.SUBSCRIPTIONS_REFRESH -> DesktopCliCommand.SubscriptionRefresh(parsed.positional.single())
                ControlOperationId.UPDATES_STATUS -> DesktopCliCommand.UpdatesStatus
                ControlOperationId.UPDATES_CHECK -> DesktopCliCommand.UpdatesCheck
                ControlOperationId.UPDATES_DOWNLOAD -> DesktopCliCommand.UpdatesDownload
                ControlOperationId.UPDATES_DISMISS -> DesktopCliCommand.UpdatesDismiss
                ControlOperationId.LOCATIONS_DELETE -> DesktopCliCommand.LocationDelete(parsed.positional.single())
                ControlOperationId.LOCATIONS_BENCHMARK -> DesktopCliCommand.LocationBenchmark(parsed.positional.single())
                ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE -> {
                    val source = if (parsed.options.keys.any { it in setOf("--input", "--qr-image") })
                        readTransferInput(parsed.options, readInput, readQrImage)
                            ?: return DesktopCliParseResult.Invalid("Could not read subscription input.")
                        else parsed.options["--source"]
                    DesktopCliCommand.SubscriptionSave(source, parsed.options["--name"], parsed.positional.singleOrNull())
                }
                ControlOperationId.SETTINGS_SHOW -> DesktopCliCommand.SettingsShow(parsed.positional.singleOrNull())
                ControlOperationId.SETTINGS_SET -> {
                    val key = parsed.positional[0]
                    val value = com.kardinal.vpncontrol.control.ControlSettingsLogic.parseTerminalValue(key, parsed.positional[1]).getOrNull()
                        ?: return DesktopCliParseResult.Invalid("Invalid setting value.")
                    DesktopCliCommand.SettingsApply(mapOf(key to value))
                }
                ControlOperationId.SETTINGS_APPLY -> {
                    val raw = readInput(parsed.options.getValue("--input")).getOrNull()
                        ?: return DesktopCliParseResult.Invalid("Could not read settings input.")
                    val values = runCatching { com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeValues(raw) }.getOrNull()
                        ?: return DesktopCliParseResult.Invalid("Invalid settings document.")
                    DesktopCliCommand.SettingsApply(values)
                }
                ControlOperationId.SOURCE_SHOW -> DesktopCliCommand.SourceShow
                ControlOperationId.SOURCE_SET -> DesktopCliCommand.SourceSet(when (parsed.positional.first()) {
                    "current-locations" -> null
                    "all" -> com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
                    else -> parsed.positional[1]
                })
                ControlOperationId.LOCATIONS_LIST -> DesktopCliCommand.LocationsList
                ControlOperationId.LOCATIONS_SHOW -> DesktopCliCommand.LocationShow(parsed.positional.single())
                ControlOperationId.LOCATIONS_SELECT -> DesktopCliCommand.Select(parsed.positional.single())
                ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_UPDATE -> {
                    val content = readTransferInput(parsed.options, readInput, readQrImage)
                        ?: return DesktopCliParseResult.Invalid("Could not read location input.")
                    DesktopCliCommand.LocationSave(content, parsed.positional.singleOrNull())
                }
                else -> return DesktopCliParseResult.Invalid("This location operation is not wired to the desktop controller yet.")
            }
            return DesktopCliParseResult.Valid(result, parsed.options["--output"], format = parsed.options["--format"] ?: "json")
        }
        return when (command) {
            "quit" -> noExtraArgs(args, DesktopCliCommand.ControlSubmit(com.kardinal.vpncontrol.model.ControlRequest(
                java.util.UUID.randomUUID().toString(), com.kardinal.vpncontrol.model.ControlCommand(ControlOperationId.QUIT))))
            "on" -> noExtraArgs(args, DesktopCliCommand.On)
            "off" -> noExtraArgs(args, DesktopCliCommand.Off)
            "restart" -> noExtraArgs(args, DesktopCliCommand.Restart)
            "status" -> noExtraArgs(args, DesktopCliCommand.Status)
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

    private fun readTransferInput(options: Map<String, String>, readInput: (String) -> Result<String>,
                                  readQrImage: (String) -> Result<String>): String? =
        options["--input"]?.let { readInput(it).getOrNull() }
            ?: options["--qr-image"]?.let { readQrImage(it).getOrNull() }
}

private sealed interface DesktopCliParseResult {
    data class Valid(val command: DesktopCliCommand, val output: String? = null, val json: Boolean = false,
                     val format: String = "json") : DesktopCliParseResult
    data class Invalid(val message: String) : DesktopCliParseResult
}
