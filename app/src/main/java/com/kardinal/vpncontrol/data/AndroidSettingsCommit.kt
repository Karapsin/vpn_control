package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.PersistedState

internal data class AndroidSettingsCommit(
    val committed: ControlCommitted<PersistedState>,
    val schedulingChanged: Boolean,
    val resultData: Map<String, com.kardinal.vpncontrol.model.ControlValue> = emptyMap(),
) {
    override fun toString(): String = "AndroidSettingsCommit(revision=${committed.revision}, schedulingChanged=$schedulingChanged)"
}
