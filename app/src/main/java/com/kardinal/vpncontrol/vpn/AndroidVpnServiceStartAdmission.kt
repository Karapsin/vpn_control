package com.kardinal.vpncontrol.vpn

/** Schedules the service command; foreground admission is deliberately tested here. */
internal object AndroidVpnServiceStartAdmission {
    fun dispatch(action: String?, promoteForeground: () -> Unit, dispatch: () -> Unit) {
        if (action != AndroidVpnService.ACTION_STOP) {
            promoteForeground()
        }
        dispatch()
    }
}
