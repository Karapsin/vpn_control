package com.kardinal.vpncontrol.shared.ui

/** Owner-provided runtime facts; the selected location is never an active-name fallback. */
data class ConnectionConfigurationPresentation(
    val runtimeRunning: Boolean?,
    val activeLocationName: String?,
    val restartRequired: Boolean?,
) {
    override fun toString() = "ConnectionConfigurationPresentation(data=<redacted>)"
}

internal sealed interface ConnectionConfigurationDetail {
    data class ActiveLocation(val name: String) : ConnectionConfigurationDetail
    data object ActiveLocationUnavailable : ConnectionConfigurationDetail
    data object RestartPending : ConnectionConfigurationDetail
    data object RestartRequirementUnavailable : ConnectionConfigurationDetail
}

internal fun connectionConfigurationDetails(
    presentation: ConnectionConfigurationPresentation?,
): List<ConnectionConfigurationDetail> = buildList {
    if (presentation == null || presentation.runtimeRunning == false) return@buildList
    val active = presentation.activeLocationName?.takeIf { presentation.runtimeRunning == true && it.isNotBlank() }
    add(active?.let(ConnectionConfigurationDetail::ActiveLocation)
        ?: ConnectionConfigurationDetail.ActiveLocationUnavailable)
    when (presentation.restartRequired) {
        true -> add(ConnectionConfigurationDetail.RestartPending)
        null -> add(ConnectionConfigurationDetail.RestartRequirementUnavailable)
        false -> Unit
    }
}

internal fun connectionConfigurationText(detail: ConnectionConfigurationDetail, strings: AppStrings): String = when (detail) {
    is ConnectionConfigurationDetail.ActiveLocation -> strings.format(UiText.ACTIVE_CONNECTION_LOCATION, detail.name)
    ConnectionConfigurationDetail.ActiveLocationUnavailable -> strings.get(UiText.ACTIVE_CONNECTION_UNKNOWN)
    ConnectionConfigurationDetail.RestartPending -> strings.get(UiText.CONNECTION_RESTART_PENDING)
    ConnectionConfigurationDetail.RestartRequirementUnavailable -> strings.get(UiText.CONNECTION_RESTART_UNKNOWN)
}
