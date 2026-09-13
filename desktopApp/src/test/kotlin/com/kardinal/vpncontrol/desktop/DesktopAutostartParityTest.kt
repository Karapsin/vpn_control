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
                val missing = DesktopAutostartCommandResult(1, "ERROR: The system cannot find the file specified.")
                if (command.first() == "powershell.exe") DesktopAutostartCommandResult(0, "ABSENT") else when (command.take(2)) {
                    listOf("schtasks", "/Query") -> if (!enabled) missing else DesktopAutostartCommandResult(0, """
                        <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                          <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
                          <Principals><Principal><UserId>S-1-5-21-1</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
                          <Actions><Exec><Command>C:\test-only\vpn-control.exe</Command><Arguments>--autostart</Arguments></Exec></Actions>
                        </Task>
                    """.trimIndent())
                    listOf("whoami.exe", "/user") -> DesktopAutostartCommandResult(0, "\"fixture\\user\",\"S-1-5-21-1\"")
                    listOf("reg", "query") -> missing
                    listOf("schtasks", "/Create") -> if (failWrites) DesktopAutostartCommandResult(1, "private OS error")
                        else { enabled = true; DesktopAutostartCommandResult(0, "") }
                    listOf("schtasks", "/Delete") -> if (failWrites) DesktopAutostartCommandResult(1, "private OS error")
                        else { enabled = false; DesktopAutostartCommandResult(0, "") }
                    else -> error("Unexpected OS action: ${command.take(2)}")
                }
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
