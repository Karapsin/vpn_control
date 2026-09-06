package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Ephemeral picker action; discard on dialog close/reopen or successful completion. */
internal data class DesktopSshKeyImportAction(
    val controllerId: String?, val revision: Long, val content: String,
    val openingId: String = UUID.randomUUID().toString(),
) {
    fun request(): ControlRequest {
        val arguments = mapOf("input" to ControlValue.Text(content))
        return frontendSettingsRequest(openingId, controllerId, revision, arguments)
            .copy(command = ControlCommand(ControlOperationId.SSH_KEY_IMPORT, arguments))
    }
    override fun toString() = "DesktopSshKeyImportAction(revision=$revision, content=<redacted>)"
}

internal suspend fun submitFrontendSshKeyImport(
    action: DesktopSshKeyImportAction, session: ControlSession?,
    previewWrite: (String, Long?) -> DesktopControlWriteResponse,
): ControlResult {
    val request = action.request()
    if (session != null) return session.submit(request)
    val committed = previewWrite(action.content, action.revision)
    return ControlResult(action.controllerId, request.requestId,
        desktopGuiCommandFailure(committed.response) ?: ControlCode.OK, committed.metadata.configurationRevision,
        restartRequired = committed.metadata.restartRequired)
}
