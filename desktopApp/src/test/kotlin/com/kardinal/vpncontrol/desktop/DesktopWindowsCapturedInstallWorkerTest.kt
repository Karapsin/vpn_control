package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopWindowsCapturedInstallWorkerTest {
    @Test fun bothWorkersAreCapturedBoundedCodeNotMutableScriptFiles() {
        for (role in DesktopWindowsCapturedInstallWorker.Role.entries) {
            val arguments = DesktopWindowsCapturedInstallWorker.arguments(role,
                "00000000-0000-0000-0000-000000000001", 123)
            assertEquals(listOf("-NoLogo", "-NoProfile", "-NonInteractive", "-Command"), arguments.dropLast(1))
            assertTrue(arguments.last().length < 30000)
            val code = arguments.last()
            assertTrue(code.all { it.code < 128 })
            assertTrue(code.contains("Add-Type -TypeDefinition"))
            assertFalse(code.contains("-File"))
            assertFalse(code.contains("request.json")) // Input paths live only inside captured fixed code.
        }
    }

    @Test fun argvNeverAcceptsCallerPathsCommandsOrMalformedIdentities() {
        assertFails { DesktopWindowsCapturedInstallWorker.arguments(
            DesktopWindowsCapturedInstallWorker.Role.COORDINATOR, "'; whoami", 123) }
        assertFails { DesktopWindowsCapturedInstallWorker.arguments(
            DesktopWindowsCapturedInstallWorker.Role.ORIGINAL_USER, "00000000-0000-0000-0000-000000000001", 0) }
    }
}
