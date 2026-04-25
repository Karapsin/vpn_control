package com.kardinal.vpncontrol.desktop

import javax.swing.SwingUtilities

internal class DesktopActivationEvents {
    @Volatile
    private var showWindowHandler: (() -> Unit)? = null

    @Volatile
    private var pendingShowWindow = false

    fun setShowWindowHandler(handler: (() -> Unit)?) {
        showWindowHandler = handler
        if (handler != null && pendingShowWindow) {
            pendingShowWindow = false
            SwingUtilities.invokeLater { handler() }
        }
    }

    fun requestShowWindow() {
        val handler = showWindowHandler
        if (handler == null) {
            pendingShowWindow = true
            return
        }
        SwingUtilities.invokeLater { handler() }
    }
}
