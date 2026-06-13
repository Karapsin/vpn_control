package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopCliCommandExecutorTest {
    @Test
    fun offCommandDisablesPendingReconnectBeforeRuntimeResumes() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-cli-off-pending-resume")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppServiceFactory.createForTesting(
                store = store,
                initialWorkspace = DesktopWorkspace(
                    persistedState = PersistedState(isVpnRunning = true),
                    locations = emptyList(),
                    resumeConnectionOnLaunch = true,
                ),
            )

            val response = service.executeCliCommand(DesktopCliCommand.Off)

            assertTrue(response.success)
            assertEquals("VPN stopped.", response.message)
            assertFalse(service.shouldResumeConnectionOnLaunch())
            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )
            assertFalse(reloaded.resumeConnectionOnLaunch)
            assertFalse(reloaded.persistedState.isVpnRunning)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
