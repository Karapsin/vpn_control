package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopWindowsElevationTest {
    @Test
    fun nonWindowsLaunchDoesNotAttemptElevation() {
        var launched = false

        val exitCode = DesktopWindowsElevation.elevateIfRequired(
            args = emptyArray(),
            osName = "Linux",
            currentCommand = "/opt/vpn-control/bin/vpn-control",
            isAdministrator = { false },
            launchElevated = { _, _ ->
                launched = true
                true
            },
        )

        assertNull(exitCode)
        assertEquals(false, launched)
    }

    @Test
    fun elevatedWindowsLaunchContinuesCurrentProcess() {
        var launched = false

        val exitCode = DesktopWindowsElevation.elevateIfRequired(
            args = emptyArray(),
            osName = "Windows 11",
            currentCommand = "C:\\Program Files\\vpn-control\\vpn-control.exe",
            isAdministrator = { true },
            launchElevated = { _, _ ->
                launched = true
                true
            },
        )

        assertNull(exitCode)
        assertEquals(false, launched)
    }

    @Test
    fun nonElevatedWindowsLaunchStartsRunAsChildAndExitsParent() {
        var launchedCommand = ""
        var launchedArgs = emptyList<String>()

        val exitCode = DesktopWindowsElevation.elevateIfRequired(
            args = arrayOf("--tray"),
            osName = "Windows 11",
            currentCommand = "C:\\Users\\DKara\\AppData\\Local\\vpn-control\\vpn-control.exe",
            isAdministrator = { false },
            launchElevated = { command, args ->
                launchedCommand = command
                launchedArgs = args
                true
            },
        )

        assertEquals(0, exitCode)
        assertEquals("C:\\Users\\DKara\\AppData\\Local\\vpn-control\\vpn-control.exe", launchedCommand)
        assertTrue(launchedArgs.contains("--tray"))
        assertTrue(launchedArgs.contains(DesktopWindowsElevation.ELEVATION_ATTEMPTED_ARG))
    }

    @Test
    fun repeatedNonElevatedWindowsLaunchFailsInsteadOfLooping() {
        val messages = mutableListOf<String>()
        var launched = false

        val exitCode = DesktopWindowsElevation.elevateIfRequired(
            args = arrayOf(DesktopWindowsElevation.ELEVATION_ATTEMPTED_ARG),
            osName = "Windows 11",
            currentCommand = "C:\\vpn-control.exe",
            isAdministrator = { false },
            launchElevated = { _, _ ->
                launched = true
                true
            },
            printLine = messages::add,
        )

        assertEquals(1, exitCode)
        assertEquals(false, launched)
        assertTrue(messages.single().contains("Administrator privileges"))
    }
}
