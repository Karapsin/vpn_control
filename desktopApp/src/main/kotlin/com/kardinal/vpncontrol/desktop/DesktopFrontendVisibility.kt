package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.CountDownLatch
import javax.swing.SwingUtilities

/** Acknowledgement is produced by the actual window adapter, never by enqueueing work. */
internal class DesktopFrontendVisibility(
    private val dispatch: (() -> Unit) -> Unit = { SwingUtilities.invokeLater(it) },
    private val timeoutMillis: Long = 2_000,
) {
    @Volatile var ownerId: String? = null
    @Volatile var available: () -> Boolean = { false }
    @Volatile private var handler: ((Boolean) -> ControlCode)? = null
    private val ready = CountDownLatch(1)

    fun install(handler: ((Boolean) -> ControlCode)?) {
        this.handler = handler
        if (handler != null) ready.countDown()
    }

    fun request(visible: Boolean, expectedOwner: String? = ownerId): ControlCode {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        if (!ready.await(timeoutMillis, TimeUnit.MILLISECONDS)) return ControlCode.TIMEOUT
        if (expectedOwner == null || ownerId != expectedOwner) return ControlCode.CONFLICT
        val result = CompletableFuture<ControlCode>()
        dispatch {
            if (!result.isDone) {
                result.complete(when {
                    System.nanoTime() >= deadline -> ControlCode.TIMEOUT
                    ownerId != expectedOwner -> ControlCode.CONFLICT
                    !available() -> ControlCode.UNAVAILABLE
                    else -> runCatching { handler?.invoke(visible) ?: ControlCode.UNAVAILABLE }
                        .getOrDefault(ControlCode.UNAVAILABLE)
                })
            }
        }
        return try { result.get((deadline - System.nanoTime()).coerceAtLeast(1), TimeUnit.NANOSECONDS) }
        catch (_: Exception) { result.cancel(false); ControlCode.TIMEOUT }
    }
}
