package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopConnectionNameLogicTest {
    @Test
    fun activeConnectionNamePrefersCurrentRuntimeMode() {
        assertEquals(
            "Proxy",
            DesktopConnectionNameLogic.activeConnectionName(
                currentRuntimeMode = AppMode.PROXY_ONLY,
                configuredMode = AppMode.VPN,
            ),
        )
    }

    @Test
    fun activeConnectionNameFallsBackToConfiguredMode() {
        assertEquals(
            "VPN",
            DesktopConnectionNameLogic.activeConnectionName(
                currentRuntimeMode = null,
                configuredMode = AppMode.VPN,
            ),
        )
    }
}
