package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopLocationEditorTest {
    @Test
    fun addAndEditPersistRealConfigsAndRemapTheSelection() {
        val directory = Files.createTempDirectory("vpn-control-location-editor")
        try {
            val service = DesktopAppServiceFactory.createForTesting(
                store = DesktopStateStore(directory),
                initialWorkspace = DesktopWorkspace(PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS), emptyList()),
            )
            val added = service.saveLocation("socks://127.0.0.1:1080#First").getOrThrow()
            assertEquals("First", added.name)
            assertEquals("127.0.0.1", added.server)
            assertFalse(added.benchmarkDetail.contains("test ok"))
            service.applyLocationSelection(added.index).getOrThrow()
            val edited = service.saveLocation("socks://127.0.0.2:2080#Edited", added.index, added.rawLink).getOrThrow()
            assertEquals(added.index, edited.index)
            assertEquals("Edited", edited.name)
            assertEquals(edited.rawLink, service.state.selectedProfileRawLink)
            val stored = DesktopStateStore(directory).loadWorkspace(DesktopWorkspace(PersistedState(), emptyList()))
            assertEquals(listOf(edited.rawLink), stored.persistedState.savedLocations)
            assertEquals("127.0.0.2", LocationConfigs.decodeStoredLocation(stored.locations.single().rawLink).server)
            assertFalse(service.saveLocation("socks://127.0.0.3:3080#Stale", added.index, added.rawLink).isSuccess)
            assertEquals(edited.rawLink, service.desktopLocations.single().rawLink)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun invalidDuplicateAndUndurableEditsDoNotChangeSavedRecords() {
        val directory = Files.createTempDirectory("vpn-control-location-editor-failure")
        try {
            val service = DesktopAppServiceFactory.createForTesting(
                store = DesktopStateStore(directory),
                initialWorkspace = DesktopWorkspace(PersistedState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS), emptyList()),
            )
            val added = service.saveLocation("socks://127.0.0.1:1080#First").getOrThrow()
            assertTrue(service.saveLocation("invalid").isFailure)
            assertTrue(service.saveLocation(added.rawLink).isFailure)
            assertEquals(listOf(added.rawLink), service.desktopLocations.map { it.rawLink })
            Files.move(directory.resolve("workspace.json"), directory.resolve("prior-workspace.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            assertTrue(service.saveLocation("socks://127.0.0.2:1080#New", added.index, added.rawLink).isFailure)
            assertEquals(listOf(added.rawLink), service.desktopLocations.map { it.rawLink })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun subscriptionSourceRejectsLocationWrites() {
        val directory = Files.createTempDirectory("vpn-control-location-editor-readonly")
        try {
            val service = DesktopAppServiceFactory.createForTesting(
                store = DesktopStateStore(directory),
                initialWorkspace = DesktopWorkspace(PersistedState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION), emptyList()),
            )
            assertTrue(service.saveLocation("socks://127.0.0.1:1080#First").isFailure)
            assertTrue(service.desktopLocations.isEmpty())
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
