package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Subscription URLs are explicit editor input, never routine presentation or diagnostic data. */
internal data class DesktopSubscriptionDraft(
    val controllerId: String?, val revision: Long, val subscriptionId: String?,
    val source: String, val name: String,
    val openingId: String = UUID.randomUUID().toString(), val failure: ControlCode? = null,
) {
    fun editName(value: String) = copy(name = value.take(80))
    fun request(): ControlRequest {
        val arguments = buildMap<String, ControlValue> {
            subscriptionId?.let { put("id", ControlValue.Text(it)) }
            put("source", ControlValue.Text(source))
            put("name", ControlValue.Text(name))
        }
        return frontendSettingsRequest(openingId, controllerId, revision, arguments).copy(command = ControlCommand(
            if (subscriptionId == null) ControlOperationId.SUBSCRIPTIONS_ADD else ControlOperationId.SUBSCRIPTIONS_UPDATE,
            arguments))
    }
    override fun toString() = "DesktopSubscriptionDraft(revision=$revision, input=<redacted>)"

    companion object {
        /** ADD uses a coherent owner read; UPDATE uses SUBSCRIPTIONS_SHOW for the exact stable ID. */
        fun from(result: ControlResult, subscriptionId: String?): DesktopSubscriptionDraft {
            require(result.ok)
            if (subscriptionId != null) require((result.data["id"] as? ControlValue.Text)?.value == subscriptionId)
            return DesktopSubscriptionDraft(result.controllerId, result.configurationRevision, subscriptionId,
                if (subscriptionId == null) "" else (result.data.getValue("source") as ControlValue.Text).value,
                if (subscriptionId == null) "" else (result.data.getValue("name") as ControlValue.Text).value)
        }
    }
}
