package com.kardinal.vpncontrol

internal class AndroidConnectionActionsService(
    private val controller: MainController,
    private val connectionLifecycle: AndroidConnectionLifecycleService,
    private val launchTrackedBusyOperation: (suspend () -> Unit) -> Unit,
) {
    fun onVpnPermissionGranted() {
        controller.onVpnPermissionGranted()
    }

    fun toggleVpn() {
        launchTrackedBusyOperation {
            connectionLifecycle.toggleConnection()
        }
    }
}
