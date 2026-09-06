package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*

internal data class DesktopFrontendRoutingDraft(val owner: String?, val revision: Long, val domains: String,
    val openingId: String = java.util.UUID.randomUUID().toString(), val failure: ControlCode? = null,
    val committedDomains: String = domains) {
    fun request(): ControlRequest {
        val args = mapOf("key" to ControlValue.Text("direct-domains"), "value" to ControlValue.Text(domains))
        return frontendSettingsRequest(openingId, owner, revision, args).copy(command = ControlCommand(ControlOperationId.ROUTING_SET, args))
    }
    override fun toString() = "DesktopFrontendRoutingDraft(revision=$revision, input=<redacted>)"
    companion object {
        fun from(result: ControlResult): DesktopFrontendRoutingDraft {
            require(result.ok)
            val values = (result.data.getValue("routing") as ControlValue.ObjectValue).values
            val rules = com.kardinal.vpncontrol.data.RoutingRulesTransfer.import(ControlProtocolCodec.encodeValues(values))
            return DesktopFrontendRoutingDraft(result.controllerId, result.configurationRevision, rules.directDomainSuffixes.joinToString("\n"))
        }
    }
}

internal fun desktopFrontendGuardedRequest(frame: DesktopPresentationSnapshot, command: ControlCommand,
    openingId: String): ControlRequest = frontendSettingsRequest(openingId, frame.controllerId, frame.configurationRevision,
    command.arguments, command.operation.wireName + ":" + ControlProtocolCodec.encodeValues(command.arguments)).copy(command = command)
