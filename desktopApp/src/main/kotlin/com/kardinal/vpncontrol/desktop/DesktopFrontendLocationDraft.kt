package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.util.UUID

internal data class DesktopLocationDraft(val controllerId: String?, val revision: Long,
    val configurationId: String?, val content: String, val openingId: String = UUID.randomUUID().toString()) {
    fun request(): ControlRequest {
        val arguments = buildMap<String, ControlValue> {
            configurationId?.let { put("id", ControlValue.Text(it)) }
            put("input", ControlValue.Text(content))
        }
        return frontendSettingsRequest(openingId, controllerId, revision, arguments).copy(command = ControlCommand(
            if (configurationId == null) ControlOperationId.LOCATIONS_ADD else ControlOperationId.LOCATIONS_UPDATE, arguments))
    }
    override fun toString() = "DesktopLocationDraft(revision=$revision, content=<redacted>)"
    companion object {
        fun from(result: ControlResult, id: String?): DesktopLocationDraft {
            require(result.ok)
            if (id != null) require((result.data["id"] as? ControlValue.Text)?.value == id)
            return DesktopLocationDraft(result.controllerId, result.configurationRevision, id,
                if (id == null) "" else (result.data.getValue("configuration") as ControlValue.Text).value)
        }
    }
}
