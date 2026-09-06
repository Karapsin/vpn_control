package com.kardinal.vpncontrol.desktop

/** Mutation result and commit metadata captured before releasing the commit monitor. */
internal data class DesktopControlWriteResponse(
    val response: DesktopCliResponse,
    val metadata: DesktopControlMetadata,
)

internal data class DesktopControlReadSnapshot(
    val metadata: DesktopControlMetadata,
    val values: Result<Map<String, com.kardinal.vpncontrol.model.ControlValue>>,
    val code: com.kardinal.vpncontrol.model.ControlCode = if (values.isSuccess)
        com.kardinal.vpncontrol.model.ControlCode.OK else com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT,
)

internal data class DesktopControlSettingsSnapshot(
    val metadata: DesktopControlMetadata,
    val values: Map<String, com.kardinal.vpncontrol.model.ControlValue>,
)

/** Read together under the owner's commit monitor; contains no configuration content. */
internal data class DesktopControlMetadata(val configurationRevision: Long, val restartRequired: Boolean) {
    init { require(configurationRevision >= 0) }
}
