package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.data.LocationConfigs
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopCliCommandExecutorTest {
    @Test
    fun guiAndCliSelectionBothRejectUndurableChangesWithoutPublishingThem() = runTest {
        val directory = Files.createTempDirectory("vpn-control-selection-persistence")
        try {
            val records = listOf("First", "Second").mapIndexed { index, name ->
                DesktopLocationRecord(index + 1, "", LocationConfigs.normalizeStoredReference(
                    "socks://127.0.0.1:${1080 + index}#$name"), name, "127.0.0.1", "SOCKS", "", true, index == 0)
            }
            val store = DesktopStateStore(directory)
            val service = DesktopAppServiceFactory.createForTesting(
                store = store,
                initialWorkspace = DesktopWorkspace(PersistedState(
                    profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                    savedLocations = records.map { it.rawLink }, currentLocations = records.map { it.rawLink },
                    selectedProfileRawLink = records[0].rawLink, selectedProfileName = "First",
                    selectedProfileServer = "127.0.0.1",
                ), records),
            )
            val initialSelection = service.state.selectedProfileRawLink
            val initialRecords = service.desktopLocations
            val primary = directory.resolve("workspace.json")
            if (Files.exists(primary)) Files.move(primary, directory.resolve("prior-workspace.json"))
            Files.createDirectory(primary)
            Files.createDirectory(directory.resolve("workspace-recovery.json"))

            assertTrue(service.applyLocationSelection(2).isFailure)
            assertEquals(initialSelection, service.state.selectedProfileRawLink)
            assertEquals(initialRecords, service.desktopLocations)

            val cli = service.executeCliCommand(DesktopCliCommand.Select("Second"))
            assertFalse(cli.success)
            assertEquals(1, cli.exitCode)
            assertEquals("PERSISTENCE_FAILED", cli.message)
            assertEquals(initialSelection, service.state.selectedProfileRawLink)
            assertEquals(initialRecords, service.desktopLocations)
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun statusReportsReachableHeadlessServiceWithoutChangingReconnectIntent() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-cli-status")
        try {
            val service = DesktopAppServiceFactory.createForTesting(
                store = DesktopStateStore(tempDir),
                initialWorkspace = DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                    resumeConnectionOnLaunch = false,
                ),
            )

            val response = service.executeCliCommand(DesktopCliCommand.Status)

            assertTrue(response.success)
            assertEquals("VPN is off", response.message)
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

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
