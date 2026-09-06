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
            is DesktopCliCommand.ControlFrontendIdentityRead -> "$COMMAND_PREFIX\tfrontend-identity\t${encodeText(command.requestId)}\t${encodeText(command.frontendId)}"
            is DesktopCliCommand.ControlPresentationRead -> "$COMMAND_PREFIX\tcontrol-presentation\t${encodeText(command.requestId)}\t${encodeText(command.controllerId.orEmpty())}"
            is DesktopCliCommand.ControlSnapshotRead -> "$COMMAND_PREFIX\tcontrol-snapshot\t${encodeText(command.controllerId.orEmpty())}"
            is DesktopCliCommand.ControlFrontendLease -> "$COMMAND_PREFIX\tfrontend-lease\t${encodeText(command.requestId)}\t${encodeText(command.controllerId)}\t${encodeText(command.frontendId)}\t${command.action.name}"
            is DesktopCliCommand.ControlSubmit -> "$COMMAND_PREFIX\tcontrol-submit\t${encodeText(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeRequest(command.request))}"
            DesktopCliCommand.On -> "$COMMAND_PREFIX\ton"
            DesktopCliCommand.Off -> "$COMMAND_PREFIX\toff"
            DesktopCliCommand.Restart -> "$COMMAND_PREFIX\trestart"
            DesktopCliCommand.RoutingShow -> "$COMMAND_PREFIX\trouting-show"
            DesktopCliCommand.RoutingExport -> "$COMMAND_PREFIX\trouting-export"
            DesktopCliCommand.Unsupported -> "$COMMAND_PREFIX\tunsupported"
            DesktopCliCommand.Languages -> "$COMMAND_PREFIX\tlanguages"
            DesktopCliCommand.SshKeyStatus -> "$COMMAND_PREFIX\tssh-key-status"
            DesktopCliCommand.Stats -> "$COMMAND_PREFIX\tstats"
            DesktopCliCommand.DiagnosticsExport -> "$COMMAND_PREFIX\tdiagnostics-export"
            is DesktopCliCommand.Logs -> "$COMMAND_PREFIX\tlogs\t${command.limit}"
            is DesktopCliCommand.SshKeyImport -> "$COMMAND_PREFIX\tssh-key-import\t${encodeText(command.content)}"
            is DesktopCliCommand.RoutingSet -> "$COMMAND_PREFIX\trouting-set\t${encodeText(command.key)}\t${encodeText(command.value)}"
            is DesktopCliCommand.RoutingImport -> "$COMMAND_PREFIX\trouting-import\t${encodeText(command.content)}"
            DesktopCliCommand.Status -> "$COMMAND_PREFIX\tstatus"
            DesktopCliCommand.FindBest -> "$COMMAND_PREFIX\tfind-best"
            is DesktopCliCommand.Select -> "$COMMAND_PREFIX\tselect\t${encodeText(command.target)}"
            DesktopCliCommand.LocationsList -> "$COMMAND_PREFIX\tlocations-list"
            DesktopCliCommand.LocationsExport -> "$COMMAND_PREFIX\tlocations-export"
            is DesktopCliCommand.LocationsImport -> "$COMMAND_PREFIX\tlocations-import\t${encodeText(command.content)}"
            DesktopCliCommand.SourceShow -> "$COMMAND_PREFIX\tsource-show"
            DesktopCliCommand.SubscriptionsList -> "$COMMAND_PREFIX\tsubscriptions-list"
            is DesktopCliCommand.SubscriptionShow -> "$COMMAND_PREFIX\tsubscriptions-show\t${encodeText(command.id)}"
            is DesktopCliCommand.SubscriptionDelete -> "$COMMAND_PREFIX\tsubscriptions-delete\t${encodeText(command.id)}"
            is DesktopCliCommand.SubscriptionRefresh -> "$COMMAND_PREFIX\tsubscriptions-refresh\t${encodeText(command.target)}"
            DesktopCliCommand.UpdatesStatus -> "$COMMAND_PREFIX\tupdates-status"
            DesktopCliCommand.OperationsList -> "$COMMAND_PREFIX\toperations-list"
            is DesktopCliCommand.OperationStatus -> "$COMMAND_PREFIX\toperations-status\t${encodeText(command.id)}"
            is DesktopCliCommand.OperationWait -> "$COMMAND_PREFIX\toperations-wait\t${encodeText(command.id)}"
            is DesktopCliCommand.OperationCancel -> "$COMMAND_PREFIX\toperations-cancel\t${encodeText(command.id)}"
            DesktopCliCommand.UpdatesCheck -> "$COMMAND_PREFIX\tupdates-check"
            DesktopCliCommand.UpdatesDownload -> "$COMMAND_PREFIX\tupdates-download"
            DesktopCliCommand.UpdatesDismiss -> "$COMMAND_PREFIX\tupdates-dismiss"
            is DesktopCliCommand.LocationDelete -> "$COMMAND_PREFIX\tlocations-delete\t${encodeText(command.target)}"
            is DesktopCliCommand.LocationBenchmark -> "$COMMAND_PREFIX\tlocations-benchmark\t${encodeText(command.target)}" +
                (command.configurationId?.let { "\t${encodeText(it)}" } ?: "")
            is DesktopCliCommand.SubscriptionSave -> "$COMMAND_PREFIX\tsubscriptions-save\t${encodeOptional(command.source)}\t${encodeOptional(command.name)}\t${encodeOptional(command.id)}"
            is DesktopCliCommand.SettingsShow -> "$COMMAND_PREFIX\tsettings-show\t${encodeText(command.key.orEmpty())}"
            is DesktopCliCommand.SettingsApply -> "$COMMAND_PREFIX\tsettings-apply\t${encodeText(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(command.values))}"
            is DesktopCliCommand.SourceSet -> "$COMMAND_PREFIX\tsource-set\t${encodeText(command.subscriptionId.orEmpty())}"
            is DesktopCliCommand.LocationShow -> "$COMMAND_PREFIX\tlocations-show\t${encodeText(command.target)}"
            is DesktopCliCommand.LocationSave -> "$COMMAND_PREFIX\tlocations-save\t${encodeText(command.content)}\t${encodeText(command.target.orEmpty())}" +
                (command.configurationId?.let { "\t${encodeText(it)}" } ?: "")
        }
    }

    fun decodeCommand(line: String): Result<DesktopCliCommand> {
        return runCatching {
            val parts = line.split('\t')
            if (parts.firstOrNull() != COMMAND_PREFIX) {
                throw IllegalArgumentException("Unsupported activation command.")
            }
            when (parts.getOrNull(1)) {
                "frontend-identity" -> {
                    require(parts.size == 4)
                    DesktopCliCommand.ControlFrontendIdentityRead(decodeText(parts[2]), decodeText(parts[3])).also { require(it.valid()) }
                }
                "frontend-lease" -> {
                    require(parts.size == 6)
                    DesktopCliCommand.ControlFrontendLease(decodeText(parts[2]), decodeText(parts[3]), decodeText(parts[4]),
                        DesktopFrontendLeaseAction.valueOf(parts[5])).also { require(it.valid()) }
                }
                "control-presentation" -> { require(parts.size == 4); DesktopCliCommand.ControlPresentationRead(
                    decodeText(parts[2]).also { require(it.isNotBlank()) }, decodeText(parts[3]).takeIf { it.isNotEmpty() }) }
                "control-snapshot" -> { require(parts.size == 3); DesktopCliCommand.ControlSnapshotRead(decodeText(parts[2]).takeIf { it.isNotEmpty() }) }
                "on" -> DesktopCliCommand.On
                "off" -> DesktopCliCommand.Off
                "restart" -> { require(parts.size == 2); DesktopCliCommand.Restart }
                "routing-show" -> { require(parts.size == 2); DesktopCliCommand.RoutingShow }
                "routing-export" -> { require(parts.size == 2); DesktopCliCommand.RoutingExport }
                "unsupported" -> { require(parts.size == 2); DesktopCliCommand.Unsupported }
                "languages" -> { require(parts.size == 2); DesktopCliCommand.Languages }
                "ssh-key-status" -> { require(parts.size == 2); DesktopCliCommand.SshKeyStatus }
                "stats" -> { require(parts.size == 2); DesktopCliCommand.Stats }
                "diagnostics-export" -> { require(parts.size == 2); DesktopCliCommand.DiagnosticsExport }
                "logs" -> { require(parts.size == 3); DesktopCliCommand.Logs(parts[2].toInt().also { require(it >= 0) }) }
                "ssh-key-import" -> { require(parts.size == 3); DesktopCliCommand.SshKeyImport(decodeText(parts[2])) }
                "routing-set" -> { require(parts.size == 4); DesktopCliCommand.RoutingSet(decodeText(parts[2]), decodeText(parts[3])) }
                "routing-import" -> { require(parts.size == 3); DesktopCliCommand.RoutingImport(decodeText(parts[2])) }
                "status" -> DesktopCliCommand.Status
                "find-best" -> DesktopCliCommand.FindBest
                "source-show" -> { require(parts.size == 2); DesktopCliCommand.SourceShow }
                "updates-status" -> { require(parts.size == 2); DesktopCliCommand.UpdatesStatus }
                "control-submit" -> { require(parts.size == 3); DesktopCliCommand.ControlSubmit(com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeRequest(decodeText(parts[2]))) }
                "operations-list" -> { require(parts.size == 2); DesktopCliCommand.OperationsList }
                "operations-status" -> { require(parts.size == 3); DesktopCliCommand.OperationStatus(decodeText(parts[2]).also { require(it.isNotBlank()) }) }
                "operations-wait" -> { require(parts.size == 3); DesktopCliCommand.OperationWait(decodeText(parts[2]).also { require(it.isNotBlank()) }) }
                "operations-cancel" -> { require(parts.size == 3); DesktopCliCommand.OperationCancel(decodeText(parts[2]).also { require(it.isNotBlank()) }) }
                "updates-check" -> { require(parts.size == 2); DesktopCliCommand.UpdatesCheck }
                "updates-download" -> { require(parts.size == 2); DesktopCliCommand.UpdatesDownload }
                "updates-dismiss" -> { require(parts.size == 2); DesktopCliCommand.UpdatesDismiss }
                "subscriptions-list" -> { require(parts.size == 2); DesktopCliCommand.SubscriptionsList }
                "subscriptions-show" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SubscriptionShow(decodeText(parts[2]))
                }
                "subscriptions-delete" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SubscriptionDelete(decodeText(parts[2]))
                }
                "subscriptions-refresh" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SubscriptionRefresh(decodeText(parts[2]))
                }
                "locations-delete" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.LocationDelete(decodeText(parts[2]))
                }
                "locations-benchmark" -> {
                    require(parts.size in 3..4)
                    DesktopCliCommand.LocationBenchmark(decodeText(parts[2]), parts.getOrNull(3)?.let(::decodeText))
                }
                "subscriptions-save" -> {
                    require(parts.size == 5)
                    DesktopCliCommand.SubscriptionSave(decodeOptional(parts[2]), decodeOptional(parts[3]), decodeOptional(parts[4]))
                }
                "settings-show" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SettingsShow(decodeText(parts[2]).takeIf { it.isNotBlank() })
                }
                "settings-apply" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SettingsApply(com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeValues(decodeText(parts[2])))
                }
                "source-set" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.SourceSet(decodeText(parts[2]).takeIf { it.isNotBlank() })
                }
                "locations-list" -> {
                    require(parts.size == 2)
                    DesktopCliCommand.LocationsList
                }
                "locations-export" -> { require(parts.size == 2); DesktopCliCommand.LocationsExport }
                "locations-import" -> { require(parts.size == 3); DesktopCliCommand.LocationsImport(decodeText(parts[2])) }
                "locations-show" -> {
                    require(parts.size == 3)
                    DesktopCliCommand.LocationShow(decodeText(parts[2]).also { require(it.isNotBlank()) })
                }
                "locations-save" -> {
                    require(parts.size in 4..5)
                    DesktopCliCommand.LocationSave(decodeText(parts[2]), decodeText(parts[3]).takeIf { it.isNotBlank() },
                        parts.getOrNull(4)?.let(::decodeText))
                }
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

    private fun encodeOptional(value: String?): String = value?.let { "v${encodeText(it)}" } ?: "-"

    private fun decodeOptional(value: String): String? {
        if (value == "-") return null
        require(value.startsWith("v"))
        return decodeText(value.drop(1))
    }

    private fun decodeText(value: String): String {
        return String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8)
    }
}
