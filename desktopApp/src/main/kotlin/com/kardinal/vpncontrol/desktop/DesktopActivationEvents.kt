package com.kardinal.vpncontrol.desktop

import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.swing.SwingUtilities

internal class DesktopActivationEvents(
    private val commandTimeoutMillis: Long = 600_000L,
    private val handlerTimeoutMillis: Long = 5_000L,
) {
    init { require(commandTimeoutMillis > 0 && handlerTimeoutMillis > 0) }
    private val cliHandlerMonitor = Object()

    @Volatile
    private var showWindowHandler: (() -> Unit)? = null

    @Volatile
    private var pendingShowWindow = false

    @Volatile
    private var cliCommandHandler: ((DesktopCliCommand, CompletableFuture<DesktopCliResponse>) -> Unit)? = null

    fun setShowWindowHandler(handler: (() -> Unit)?) {
        showWindowHandler = handler
        if (handler != null && pendingShowWindow) {
            pendingShowWindow = false
            SwingUtilities.invokeLater { handler() }
        }
    }

    fun setCliCommandHandler(handler: ((DesktopCliCommand, CompletableFuture<DesktopCliResponse>) -> Unit)?) {
        synchronized(cliHandlerMonitor) {
            cliCommandHandler = handler
            cliHandlerMonitor.notifyAll()
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

    fun requestCliCommand(command: DesktopCliCommand): DesktopCliResponse {
        val handler = try { awaitCliCommandHandler(handlerTimeoutMillis) }
        catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return DesktopCliResponse.failure("UNAVAILABLE", exitCode = 2)
        }
            ?: return DesktopCliResponse.failure("VPN Control desktop app is not ready.", exitCode = 2)
        val future = CompletableFuture<DesktopCliResponse>()
        try {
            // The handler dispatches into its owner's coroutine scope; only window actions need Swing.
            handler(command, future)
        } catch (_: Exception) {
            return DesktopCliResponse.failure("OUTCOME_UNKNOWN", exitCode = 2)
        }
        return try { future.get(commandTimeoutMillis, TimeUnit.MILLISECONDS) }
        catch (_: TimeoutException) { DesktopCliResponse.failure("TIMEOUT", exitCode = 2) }
        catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            DesktopCliResponse.failure("OUTCOME_UNKNOWN", exitCode = 2)
        } catch (_: Exception) { DesktopCliResponse.failure("OUTCOME_UNKNOWN", exitCode = 2) }
    }

    private fun awaitCliCommandHandler(timeoutMillis: Long = 5_000L): (
        (DesktopCliCommand, CompletableFuture<DesktopCliResponse>) -> Unit
    )? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        synchronized(cliHandlerMonitor) {
            while (cliCommandHandler == null) {
                val remainingMillis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                if (remainingMillis <= 0L) break
                cliHandlerMonitor.wait(remainingMillis)
            }
            return cliCommandHandler
        }
    }
}
