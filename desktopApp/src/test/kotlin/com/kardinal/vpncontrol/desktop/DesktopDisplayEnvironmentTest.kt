package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopDisplayEnvironmentTest {
    @Test
    fun linuxRequiresDisplayOrWaylandEnvironment() {
        assertFalse(
            isDesktopDisplayAvailable(
                osName = "Linux",
                env = emptyMap(),
                isHeadless = false,
            ),
        )
        assertTrue(
            isDesktopDisplayAvailable(
                osName = "Linux",
                env = mapOf("DISPLAY" to ":0"),
                isHeadless = false,
            ),
        )
        assertTrue(
            isDesktopDisplayAvailable(
                osName = "Linux",
                env = mapOf("WAYLAND_DISPLAY" to "wayland-0"),
                isHeadless = false,
            ),
        )
    }

    @Test
    fun headlessEnvironmentIsRejectedBeforeStartingDesktop() {
        assertFalse(
            isDesktopDisplayAvailable(
                osName = "Linux",
                env = mapOf("DISPLAY" to ":0"),
                isHeadless = true,
            ),
        )
    }

    @Test
    fun nonLinuxHeadfulDesktopDoesNotRequireUnixDisplayEnvironment() {
        assertTrue(
            isDesktopDisplayAvailable(
                osName = "Windows 11",
                env = emptyMap(),
                isHeadless = false,
            ),
        )
        assertTrue(
            isDesktopDisplayAvailable(
                osName = "Mac OS X",
                env = emptyMap(),
                isHeadless = false,
            ),
        )
    }
}
