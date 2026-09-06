package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopStateStoreDurabilityTest {
    @Test
    fun unwritableInitialWorkspaceDoesNotPretendDefaultsWerePersisted() {
        val file = Files.createTempFile("vpn-control-not-a-directory", ".tmp")
        try {
            assertFailsWith<DesktopPersistenceException> {
                DesktopStateStore(file).loadWorkspace(DesktopWorkspace(PersistedState(), emptyList()))
            }
        } finally {
            Files.deleteIfExists(file)
        }
    }

    @Test
    fun failedRuntimeConfigWriteAndDeleteAreObservable() = runTest {
        val directory = Files.createTempDirectory("vpn-control-runtime-write-failure")
        try {
            val target = Files.createDirectory(directory.resolve("runtime-config.json"))
            Files.writeString(target.resolve("keep"), "fixture")
            val store = DesktopStateStore(directory)
            assertFailsWith<DesktopPersistenceException> { store.writeRuntimeConfig("SECRET") }
            assertFailsWith<DesktopPersistenceException> { store.clearRuntimeConfig() }
            assertEquals("fixture", Files.readString(target.resolve("keep")))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun failedPrimaryAndRecoveryWritesReturnFailureAndKeepPublishedState() = runTest {
        val directory = Files.createTempDirectory("vpn-control-durability")
        try {
            val store = DesktopStateStore(directory)
            val original = DesktopWorkspace(PersistedState(profileUrl = "https://example.test/original"), emptyList())
            assertTrue(store.writeWorkspace(original).isSuccess)
            Files.move(directory.resolve("workspace.json"), directory.resolve("saved-workspace.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))

            val result = store.writeWorkspace(original.copy(persistedState = original.persistedState.copy(profileUrl = "https://example.test/new")))

            assertTrue(result.isFailure)
            assertEquals(original.persistedState, store.snapshot())
            assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun recoveryFileCountsAsDurableSuccess() = runTest {
        val directory = Files.createTempDirectory("vpn-control-durability-recovery")
        try {
            Files.createDirectory(directory.resolve("workspace.json"))
            val store = DesktopStateStore(directory)
            val expected = DesktopWorkspace(PersistedState(profileUrl = "https://example.test/recovery"), emptyList())

            assertTrue(store.writeWorkspace(expected).isSuccess)
            assertEquals(expected.persistedState, store.snapshot())
            assertEquals(expected, DesktopStateStore(directory).loadWorkspace(DesktopWorkspace(PersistedState(), emptyList())))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
