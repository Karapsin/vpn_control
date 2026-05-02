package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class DesktopRuntimeShutdownHookTest {
    @Test
    fun installRegistersHookOnlyOnce() {
        val registered = mutableListOf<Thread>()
        var stopCalls = 0
        val hook = DesktopRuntimeShutdownHook(
            stopRuntimeBlocking = { stopCalls += 1 },
            registerHook = { registered += it },
        )

        hook.install()
        hook.install()

        assertEquals(1, registered.size)
        assertEquals("vpn-control-runtime-shutdown", registered.single().name)
        assertFalse(registered.single().isAlive)
        assertEquals(0, stopCalls)
    }
}
