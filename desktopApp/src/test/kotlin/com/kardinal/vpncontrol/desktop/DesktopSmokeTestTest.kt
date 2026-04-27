package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopSmokeTestTest {
    @Test
    fun handleArgsRunsHeadlessSmokeTestWithCustomStateDir() {
        val tempDir = Files.createTempDirectory("vpn-control-smoke-test")
        val output = mutableListOf<String>()
        try {
            val exitCode = DesktopSmokeTest.handleArgs(
                args = arrayOf("--smoke-test", "--smoke-test-state-dir", tempDir.toString()),
                classLoader = javaClass.classLoader,
                printLine = output::add,
            )

            assertEquals(0, exitCode)
            assertTrue(output.any { it.contains("desktop smoke test passed") })
            assertTrue(Files.exists(tempDir.resolve("workspace.json")))
            assertTrue(Files.exists(tempDir.resolve("runtime").resolve("tools")))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun handleArgsIgnoresNormalAppLaunchArguments() {
        val exitCode = DesktopSmokeTest.handleArgs(
            args = arrayOf("--tray"),
            classLoader = javaClass.classLoader,
            printLine = {},
        )

        assertNull(exitCode)
    }
}
