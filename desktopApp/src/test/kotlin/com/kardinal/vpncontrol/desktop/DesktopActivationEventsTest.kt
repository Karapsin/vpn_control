package com.kardinal.vpncontrol.desktop

import javax.swing.SwingUtilities
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

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

    @Test
    fun cliRequestIsDeliveredToRegisteredHandler() {
        val events = DesktopActivationEvents()
        events.setCliCommandHandler { command, future ->
            future.complete(DesktopCliResponse.success("handled $command"))
        }

        val response = events.requestCliCommand(DesktopCliCommand.Off)

        assertTrue(response.success)
        assertEquals("handled Off", response.message)
    }

    private fun drainSwingEvents() {
        SwingUtilities.invokeAndWait {}
    }
}
