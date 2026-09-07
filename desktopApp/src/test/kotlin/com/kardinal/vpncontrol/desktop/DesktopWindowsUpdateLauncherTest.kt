package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopWindowsUpdateLauncherTest {
    @Test fun explicitCliOwnerRelaunchesExactSiblingGuiImage() {
        val expected = "C:\\Users\\東京 😀\\vpn-control\\vpn-control.exe"
        val inspected = mutableListOf<String>()
        assertEquals(expected, desktopWindowsUpdateLauncher(
            "C:\\Users\\東京 😀\\vpn-control\\VPN-CONTROL-CLI.EXE", { inspected += it; true }))
        assertEquals(listOf(expected), inspected)
        assertEquals(expected, desktopWindowsUpdateLauncher(expected, { true }))
    }

    @Test fun missingGuiOrUnrelatedOwnerNeverFallsBackToAnotherExecutable() {
        assertNull(desktopWindowsUpdateLauncher("C:\\app\\vpn-control-cli.exe", { false }))
        for (owner in listOf("C:\\app\\java.exe", "C:\\app\\other.exe", "vpn-control-cli.exe", "C:\\app\\..\\vpn-control.exe")) {
            assertNull(desktopWindowsUpdateLauncher(owner, { fail("Invalid owner must not search for a launcher") }))
        }
    }
}
