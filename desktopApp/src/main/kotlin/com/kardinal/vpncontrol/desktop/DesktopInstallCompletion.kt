package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlResult

/** Only an exact protected-ready handoff allows the GUI to release its waited process. */
internal fun desktopInstallHandoffIsFinal(result: ControlResult): Boolean =
    !result.final && result.code == ControlCode.ACCEPTED && !result.operationId.isNullOrBlank() &&
        (result.data["jobId"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value?.let(DesktopInstallJobNames::validJob) == true &&
        result.data["handoffReady"] == com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true)
