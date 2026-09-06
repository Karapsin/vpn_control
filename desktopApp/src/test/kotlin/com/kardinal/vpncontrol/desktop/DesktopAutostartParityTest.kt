package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopAutostartParityTest {
    @Test
    fun guiAndCliUseTheSameValidatedAutostartActionAndRevisionAccounting() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-autostart-parity")
        var enabled = false
        var failWrites = false
        var osCalls = 0
        val manager = DesktopAutostartManager(
            platform = DesktopAutostartPlatform.WINDOWS,
            commandResolver = { "C:\\test-only\\vpn-control.exe" },
            commandRunner = { command ->
                osCalls++
                val code = when (command.take(2)) {
                    listOf("schtasks", "/Query") -> if (enabled) 0 else 1
                    listOf("reg", "query") -> 1
                    listOf("schtasks", "/Create") -> if (failWrites) 1 else { enabled = true; 0 }
                    listOf("schtasks", "/Delete") -> if (failWrites) 1 else { enabled = false; 0 }
                    else -> error("Unexpected OS action: ${command.take(2)}")
                }
                DesktopAutostartCommandResult(code, if (code == 1) "private OS error" else "")
            },
        )
        try {
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
                autostartManager = manager, controlPlatform = ControlPlatform.WINDOWS)
            fun command(value: Boolean) = DesktopCliCommand.SettingsApply(mapOf("autostart" to ControlValue.BooleanValue(value)))
            service.setStartOnBootEnabled(true)
            assertTrue(enabled)
            assertTrue(service.state.startOnBootEnabled)
            assertEquals(1L, service.configurationRevision)
            val callsBeforeConflict = osCalls
            assertEquals("CONFLICT", service.applyControlSettings(
                mapOf("autostart" to ControlValue.BooleanValue(false)), expectedRevision = 0).exceptionOrNull()?.message)
            assertEquals(callsBeforeConflict, osCalls)
            assertTrue(enabled)
            assertTrue(service.executeCliCommand(command(true)).success)
            assertEquals(1L, service.configurationRevision)
            failWrites = true
            val failure = service.executeCliCommand(command(false))
            assertFalse(failure.success)
            assertFalse(failure.message.contains("private"))
            service.setStartOnBootEnabled(false)
            assertTrue(service.state.startOnBootEnabled)
            assertEquals(1L, service.configurationRevision)
            failWrites = false
            assertTrue(service.executeCliCommand(command(false)).success)
            assertFalse(enabled)
            assertFalse(service.state.startOnBootEnabled)
            assertEquals(2L, service.configurationRevision)
        } finally { directory.toFile().deleteRecursively() }
    }
}
