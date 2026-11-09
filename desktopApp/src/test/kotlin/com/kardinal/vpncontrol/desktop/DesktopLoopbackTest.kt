package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopLoopbackTest {
    @Test fun probesListenOnTheIpv4LoopbackAndSeeAPortHeldThere() {
        DesktopLoopback.serverSocket().use { held ->
            assertTrue(held.inetAddress.isLoopbackAddress && held.localPort > 0, "${held.localSocketAddress}")
            assertTrue(held.inetAddress.address.contentEquals(byteArrayOf(127, 0, 0, 1)), "${held.localSocketAddress}")
            assertFalse(DesktopLoopback.isPortAvailable(held.localPort), "A port held on the loopback must be refused")
        }
    }
}
