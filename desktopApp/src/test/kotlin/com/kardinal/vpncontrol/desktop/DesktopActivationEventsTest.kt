package com.kardinal.vpncontrol.desktop

import javax.swing.SwingUtilities
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopActivationEventsTest {
    @Test
    fun requestBeforeHandlerIsDeliveredWhenHandlerIsRegistered() {
        val events = DesktopActivationEvents()
        var requests = 0

        events.requestShowWindow()
        events.setShowWindowHandler { requests++ }
        events.setShowWindowHandler { requests++ }
        drainSwingEvents()

        assertEquals(1, requests)
    }

    @Test
    fun requestWithHandlerIsDeliveredImmediately() {
        val events = DesktopActivationEvents()
        var requests = 0
        events.setShowWindowHandler { requests++ }

        events.requestShowWindow()
        events.requestShowWindow()
        drainSwingEvents()

        assertEquals(2, requests)
    }

    private fun drainSwingEvents() {
        SwingUtilities.invokeAndWait {}
    }
}
