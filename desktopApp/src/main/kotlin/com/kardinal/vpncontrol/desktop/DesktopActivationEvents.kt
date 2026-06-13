package com.kardinal.vpncontrol.desktop

import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

internal class DesktopActivationEvents {
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
        val handler = awaitCliCommandHandler()
            ?: return DesktopCliResponse.failure("VPN Control desktop app is not ready.", exitCode = 2)
        val future = CompletableFuture<DesktopCliResponse>()
        SwingUtilities.invokeLater {
            runCatching { handler(command, future) }
                .onFailure { error ->
                    future.complete(
                        DesktopCliResponse.failure(error.message ?: "VPN Control CLI command failed."),
                    )
                }
        }
        return runCatching { future.get() }
            .getOrElse { error ->
                DesktopCliResponse.failure(error.message ?: "VPN Control CLI command failed.")
            }
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
