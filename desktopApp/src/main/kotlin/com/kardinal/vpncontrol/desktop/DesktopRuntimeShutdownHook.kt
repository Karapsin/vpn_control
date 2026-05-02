package com.kardinal.vpncontrol.desktop

import java.util.concurrent.atomic.AtomicBoolean

internal class DesktopRuntimeShutdownHook(
    private val stopRuntimeBlocking: () -> Unit,
    private val registerHook: (Thread) -> Unit = { hook ->
        Runtime.getRuntime().addShutdownHook(hook)
    },
) {
    private val installed = AtomicBoolean(false)
    private val hook = Thread(
        {
            stopRuntimeBlocking()
        },
        "vpn-control-runtime-shutdown",
    )

    fun install() {
        if (installed.compareAndSet(false, true)) {
            registerHook(hook)
        }
    }
}
