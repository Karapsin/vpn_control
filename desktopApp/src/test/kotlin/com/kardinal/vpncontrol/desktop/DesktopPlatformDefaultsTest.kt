package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopPlatformDefaultsTest {
    @Test
    fun defaultModeIsProxyOnlyOnMacos() {
        assertEquals(AppMode.PROXY_ONLY, defaultDesktopAppMode("Mac OS X"))
        assertEquals(AppMode.PROXY_ONLY, defaultDesktopAppMode("Darwin"))
    }

    @Test
    fun defaultModeRemainsVpnOnLinuxAndWindows() {
        assertEquals(AppMode.VPN, defaultDesktopAppMode("Linux"))
        assertEquals(AppMode.VPN, defaultDesktopAppMode("Windows 11"))
    }
}
