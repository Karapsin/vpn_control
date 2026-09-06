package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlSnapshot
import com.kardinal.vpncontrol.model.ControlValue

/** Status projection contains opaque identities, never location content or credentials. */
fun ControlSnapshot.toControlValues(): Map<String, ControlValue> = mapOf(
    "runtimeRunning" to ControlValue.BooleanValue(runtimeRunning),
    "selectedLocationId" to selectedLocationId.controlText(),
    "activeLocationId" to activeLocationId.controlText(),
    "configuredMode" to ControlValue.Text(configuredMode.controlName()),
    "activeMode" to activeMode?.controlName().controlText(),
    "runtimeId" to runtimeId.controlText(),
    "runtimeStartedAt" to (runtimeStartedAt?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
    "restartRequired" to ControlValue.BooleanValue(restartRequired),
)

private fun String?.controlText(): ControlValue = this?.let(ControlValue::Text) ?: ControlValue.Null
private fun AppMode.controlName(): String = when (this) {
    AppMode.VPN -> "vpn"
    AppMode.PROXY_ONLY -> "proxy-only"
}
