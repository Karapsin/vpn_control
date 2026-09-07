package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppInstallSessionPhase
import com.kardinal.vpncontrol.AppInstallSessionStatus
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue

/** Receipt projection only. Reading a journal never starts, cancels, or cleans an installer. */
internal object DesktopRecoveredInstallPresentation {
    fun project(previous: AppUpdateState, recovery: List<DesktopInstallCorrelationRecovery>): AppUpdateState {
        val bound = recovery.filter { it.binding != null }
        val active = bound.filter { it.blocksInstallation }
        if (active.isEmpty() && previous.phase == AppUpdatePhase.INSTALLING && previous.installSession == null)
            return previous // A newly preparing attempt has not published its journal yet.
        if (active.size > 1) return previous.copy(phase = AppUpdatePhase.INSTALLING,
            installSession = null, message = ControlCode.OUTCOME_UNKNOWN.wireName)
        val selected = active.singleOrNull()
            ?: bound.singleOrNull { it.binding?.jobId == previous.installSession?.receiptId }
            ?: bound.singleOrNull()
            ?: return previous
        val phase = when {
            selected.notStarted -> if (selected.code == ControlCode.CANCELLED)
                AppInstallSessionPhase.CANCELLED else AppInstallSessionPhase.FAILED
            else -> when (selected.receipt?.phase) {
                DesktopInstallJobPhase.PREPARING -> AppInstallSessionPhase.PREPARING
                DesktopInstallJobPhase.AUTHORIZED -> AppInstallSessionPhase.STAGED
                DesktopInstallJobPhase.WAITING_FOR_EXIT, DesktopInstallJobPhase.INSTALLING -> AppInstallSessionPhase.HANDED_OFF
                DesktopInstallJobPhase.SUCCEEDED -> AppInstallSessionPhase.INSTALLED
                DesktopInstallJobPhase.FAILED -> AppInstallSessionPhase.FAILED
                DesktopInstallJobPhase.CANCELLED -> AppInstallSessionPhase.CANCELLED
                null -> AppInstallSessionPhase.UNKNOWN
            }
        }
        return previous.copy(
            phase = when (phase) {
                AppInstallSessionPhase.INSTALLED -> AppUpdatePhase.IDLE
                AppInstallSessionPhase.CANCELLED -> if (previous.preparedAsset != null) AppUpdatePhase.READY else AppUpdatePhase.IDLE
                AppInstallSessionPhase.FAILED -> AppUpdatePhase.FAILED
                else -> AppUpdatePhase.INSTALLING
            },
            installSession = AppInstallSessionStatus(requireNotNull(selected.binding).jobId, phase,
                previous.availableVersion, resumable = false),
            message = when (phase) {
                AppInstallSessionPhase.UNKNOWN -> ControlCode.OUTCOME_UNKNOWN.wireName
                AppInstallSessionPhase.FAILED -> selected.code.wireName
                else -> ""
            },
        )
    }

    fun values(recovery: List<DesktopInstallCorrelationRecovery>): ControlValue.ArrayValue = ControlValue.ArrayValue(
        recovery.mapNotNull { recovered ->
            val binding = recovered.binding ?: return@mapNotNull null
            val receipt = recovered.receipt
            val terminal = recovered.notStarted || receipt?.phase?.terminal == true
            ControlValue.ObjectValue(mapOf(
                "jobId" to ControlValue.Text(binding.jobId),
                "originControllerId" to ControlValue.Text(binding.correlation.controllerId),
                "originRequestId" to ControlValue.Text(binding.correlation.requestId),
                "operationId" to ControlValue.Text(binding.correlation.operationId),
                "phase" to ControlValue.Text(if (recovered.notStarted)
                    if (recovered.code == ControlCode.CANCELLED) "cancelled" else "failed"
                    else receipt?.phase?.name?.lowercase() ?: "unknown"),
                "code" to ControlValue.Text(if (terminal) recovered.code.wireName else if (receipt == null)
                    ControlCode.OUTCOME_UNKNOWN.wireName else ControlCode.ACCEPTED.wireName),
                "final" to ControlValue.BooleanValue(terminal),
                "cleanupCode" to (recovered.cleanupCode?.let { ControlValue.Text(it.wireName) } ?: ControlValue.Null),
                "installed" to when {
                    recovered.notStarted || receipt?.phase == DesktopInstallJobPhase.CANCELLED -> ControlValue.BooleanValue(false)
                    receipt?.phase == DesktopInstallJobPhase.SUCCEEDED -> ControlValue.BooleanValue(true)
                    else -> ControlValue.Null
                },
            ))
        },
    )
}
