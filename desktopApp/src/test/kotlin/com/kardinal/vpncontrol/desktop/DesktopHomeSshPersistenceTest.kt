package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.io.path.deleteRecursively
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

@OptIn(kotlin.io.path.ExperimentalPathApi::class)
class DesktopHomeSshPersistenceTest {
    @Test
    fun privateKeyIsStoredOutsideWorkspaceWithOwnerOnlyPermissions() {
        val directory = createTempDirectory("vpn-control-home-ssh-key-")
        try {
            val store = DesktopHomeSshCredentialStore(directory)
            val keyPath = store.importPrivateKey(TEST_PRIVATE_KEY)

            assertTrue(store.hasPrivateKey())
            assertTrue(keyPath.startsWith(directory.toString()))
            val storedPath = java.nio.file.Path.of(keyPath)
            if (Files.getFileAttributeView(storedPath, PosixFileAttributeView::class.java) != null) {
                assertEquals(
                    PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(storedPath),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                store.importPrivateKey("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----")
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun workspaceRoundTripPersistsSettingsButNotPrivateKeyMaterial() {
        val directory = createTempDirectory("vpn-control-home-ssh-state-")
        try {
            val settings = HomeSshRouteSettings(
                enabled = true,
                host = "ssh.example",
                port = 228,
                user = "vpn",
                hostKeys = listOf("ssh-ed25519 host-key"),
                relayPort = 10808,
                credentialVersion = 3,
            )
            val store = DesktopStateStore(directory)
            store.writeWorkspace(DesktopWorkspace(PersistedState(homeSshRouteSettings = settings), emptyList()))
            val rawWorkspace = Files.readString(directory.resolve("workspace.json"))
            val restored = DesktopStateStore(directory).loadWorkspace(
                DesktopWorkspace(PersistedState(), emptyList()),
            )

            assertEquals(settings, restored.persistedState.homeSshRouteSettings)
            assertTrue("PRIVATE KEY" !in rawWorkspace)
        } finally {
            directory.deleteRecursively()
        }
    }

    private companion object {
        const val TEST_PRIVATE_KEY =
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"
    }
}
