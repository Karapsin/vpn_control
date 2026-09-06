package com.kardinal.vpncontrol.desktop

import javax.swing.SwingUtilities
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class DesktopActivationEventsTest {
    @Test
    fun commandDispatchDoesNotRequireSwingAndTimedOutWaitDoesNotCancelOwnerResult() {
        val events = DesktopActivationEvents(commandTimeoutMillis = 1)
        lateinit var result: java.util.concurrent.CompletableFuture<DesktopCliResponse>
        events.setCliCommandHandler { _, future ->
            assertFalse(SwingUtilities.isEventDispatchThread())
            result = future
        }
        val response = events.requestCliCommand(DesktopCliCommand.FindBest)
        assertEquals(2, response.exitCode)
        assertEquals("TIMEOUT", response.message)
        assertFalse(result.isCancelled)
        assertTrue(result.complete(DesktopCliResponse.success("Completed after client wait expired")))
        assertTrue(result.get().success)
    }

    @Test
    fun dispatchExceptionsNeverExposePrivateDetailsOrClaimKnownFailure() {
        val events = DesktopActivationEvents()
        events.setCliCommandHandler { _, _ -> error("https://private.example/secret") }
        val response = events.requestCliCommand(DesktopCliCommand.On)
        assertEquals(2, response.exitCode)
        assertEquals("OUTCOME_UNKNOWN", response.message)
    }

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
