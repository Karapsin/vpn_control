package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode

/** The native runtime outcome is already established; only owned resource publication remains. */
enum class DesktopRuntimeResourceDisposition { PENDING_PUBLICATION, COMMITTED_CLEANUP_PENDING }

data class DesktopRuntimeResourceWarning(
    val code: ControlCode,
    val journalId: String,
    val disposition: DesktopRuntimeResourceDisposition,
) {
    init {
        require(code in setOf(ControlCode.PERSISTENCE_FAILED, ControlCode.PERMISSION_DENIED,
            ControlCode.CONFLICT, ControlCode.OUTCOME_UNKNOWN))
        require(journalId.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")))
    }

    override fun toString() = "DesktopRuntimeResourceWarning(code=$code, disposition=$disposition, journal=<redacted>)"
}

/** Raised only after native exit and handle disposal are confirmed. It never owns a live child. */
internal class DesktopRuntimeResourcePublicationFailure(warnings: List<DesktopRuntimeResourceWarning>) :
    java.io.IOException(ControlCode.PERSISTENCE_FAILED.name) {
    val warnings = warnings.toList().also { require(it.isNotEmpty()) }
    val runtimeStopped: Boolean get() = true
    override fun toString() = "DesktopRuntimeResourcePublicationFailure(resources=<redacted>, runtimeStopped=true)"
}
