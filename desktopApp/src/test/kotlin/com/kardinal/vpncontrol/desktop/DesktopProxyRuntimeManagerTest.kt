package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContains

class DesktopProxyRuntimeManagerTest {
    @Test
    fun windowsVpnCapabilityRequiresAdministratorPrivileges() {
        val tempDir = Files.createTempDirectory("vpn-control-windows-vpn-not-admin")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Windows 11",
                windowsAdministratorOverride = false,
            )

            assertContains(
                manager.desktopVpnCapabilityStatus(),
                "Windows VPN mode needs Administrator privileges",
            )
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windowsVpnCapabilityPassesWhenAdministratorPrivilegesAreAvailable() {
        val tempDir = Files.createTempDirectory("vpn-control-windows-vpn-admin")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Windows 11",
                windowsAdministratorOverride = true,
            )

            assertContains(manager.desktopVpnCapabilityStatus(), "ready")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}

private class InMemoryRuntimeConfigStore : com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore {
    private var config: String? = null

    override suspend fun readRuntimeConfig(): String? = config

    override suspend fun writeRuntimeConfig(configJson: String) {
        config = configJson
    }

    override suspend fun clearRuntimeConfig() {
        config = null
    }
}
