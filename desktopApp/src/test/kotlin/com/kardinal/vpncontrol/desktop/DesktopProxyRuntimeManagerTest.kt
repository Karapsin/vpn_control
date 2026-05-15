package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

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

            assertEquals(
                RuntimeStatusMessages.desktopVpnCapabilityReady(),
                manager.desktopVpnCapabilityStatus(),
            )
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun macosVpnCapabilityExplainsProxyOnlyFallback() {
        val tempDir = Files.createTempDirectory("vpn-control-macos-vpn")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Mac OS X",
            )

            val status = manager.desktopVpnCapabilityStatus()
            assertContains(status, "macOS VPN mode needs a privileged Network Extension helper")
            assertContains(status, "Proxy-only mode")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linuxVpnCapabilityFailureNamesResolvedSingBoxBinary() {
        val binaryPath = Path.of("opt", "vpn-control", "bin", "sing-box")
        val resolvedPath = binaryPath.toAbsolutePath().normalize().toString()
        val detail = linuxNetworkPrivilegesMissingDetail(
            DesktopSingBoxExecutable(
                path = binaryPath,
                source = "VPN_CONTROL_SING_BOX",
            ),
        )

        assertContains(detail, resolvedPath)
        assertContains(detail, "VPN_CONTROL_SING_BOX")
        assertContains(detail, "sudo setcap cap_net_admin,cap_net_raw+ep")
        assertContains(detail, "'$resolvedPath'")
        assertFalse(detail.contains("command -v sing-box"))
    }

    @Test
    fun linuxVpnCapabilityRequiresBothInstalledCapabilities() {
        assertFalse(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_admin=ep"))
        assertFalse(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_raw=ep"))
        assertTrue(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_admin,cap_net_raw=ep"))
    }

    @Test
    fun linuxTunMissingDetailExplainsKernelModuleMismatch() {
        val modulesRoot = Files.createTempDirectory("vpn-control-modules-root")
        try {
            Files.createDirectories(modulesRoot.resolve("7.0.3-arch1-2"))

            val detail = linuxTunBackendMissingDetail(
                currentKernel = "6.19.14-arch1-1",
                modulesRoot = modulesRoot,
            )

            assertContains(detail, "/dev/net/tun")
            assertContains(detail, "6.19.14-arch1-1")
            assertContains(detail, "7.0.3-arch1-2")
            assertContains(detail, "Reboot into an installed kernel")
            assertContains(detail, "sudo modprobe tun")
        } finally {
            modulesRoot.toFile().deleteRecursively()
        }
    }

    @Test
    fun linuxTunMissingDetailKeepsSimpleModprobeGuidanceWhenModulesExist() {
        val modulesRoot = Files.createTempDirectory("vpn-control-modules-root")
        try {
            Files.createDirectories(modulesRoot.resolve("6.19.14-arch1-1"))

            val detail = linuxTunBackendMissingDetail(
                currentKernel = "6.19.14-arch1-1",
                modulesRoot = modulesRoot,
            )

            assertContains(detail, "/dev/net/tun")
            assertContains(detail, "sudo modprobe tun")
            assertFalse(detail.contains("Reboot into an installed kernel"))
        } finally {
            modulesRoot.toFile().deleteRecursively()
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
