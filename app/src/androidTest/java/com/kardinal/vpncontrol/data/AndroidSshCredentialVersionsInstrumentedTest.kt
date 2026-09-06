package com.kardinal.vpncontrol.data

import android.system.Os
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test

/** No application workspace, owner, network, VPN service or real credential is accessed. */
class AndroidSshCredentialVersionsInstrumentedTest {
    private val versionKey = longPreferencesKey("home_ssh_credential_version")
    private fun key(label: String) = "-----BEGIN PRIVATE KEY-----\nTEST-ONLY-$label\n-----END PRIVATE KEY-----\n"

    @Test fun nativeDirectorySyncAtomicPublicationAndImmutableMigration() = fixture { root ->
        val credentials = File(root, "credentials").apply { check(mkdir()) }
        val legacy = File(credentials, "home-ssh-private-key").apply { writeText(key("old")) }
        val versions = AndroidSshCredentialVersions(credentials)
        val first = versions.stage(key("first"), 7)
        assertEquals(8L, first)
        val previous = File(requireNotNull(versions.path(7)))
        val current = File(requireNotNull(versions.path(first)))
        assertEquals(key("old"), previous.readText())
        assertEquals(key("first"), current.readText())
        assertEquals(key("old"), legacy.readText())
        assertEquals(0x180, Os.stat(current.absolutePath).st_mode and 0x1ff)
        assertEquals(0x180, Os.stat(previous.absolutePath).st_mode and 0x1ff)
        assertEquals(first, versions.stage(key("first"), first))
        val retry = AndroidSshCredentialVersions(credentials).stage(key("retry"), 7)
        assertEquals(9L, retry)
        assertEquals(key("first"), current.readText())
        assertEquals(key("retry"), File(requireNotNull(versions.path(retry))).readText())
        assertNull(versions.path(99))
        assertFalse(File(credentials, "home-ssh-key-versions").listFiles().orEmpty().any { it.name.endsWith(".tmp") })
    }

    @Test fun realDataStoreDiskFailurePreservesCommittedMetadataAndOldCredentialAfterReopen() = fixture { root ->
        val credentials = File(root, "credentials").apply { check(mkdir()) }
        val legacy = File(credentials, "home-ssh-private-key").apply { writeText(key("old")) }
        val versions = AndroidSshCredentialVersions(credentials)
        val metadata = File(root, "metadata").apply { check(mkdir()) }
        val backup = File(root, "metadata-backup")
        val target = File(metadata, "configuration.preferences_pb")
        val epoch = UUID.randomUUID().toString()
        fun open(scope: CoroutineScope) = AndroidConfigurationStore(
            PreferenceDataStoreFactory.create(scope = scope) { target },
            { prefs -> PersistedState(homeSshRouteSettings = HomeSshRouteSettings(credentialVersion = prefs[versionKey] ?: 0)) },
            epoch,
        )
        var orphanVersion = -1L
        val firstJob = SupervisorJob()
        try {
            val owner = open(CoroutineScope(firstJob + Dispatchers.IO))
            owner.edit(epoch, 0) { it[versionKey] = 0 }
            assertTrue(target.isFile)
            val failure = runCatching {
                owner.edit(epoch, 0) { prefs ->
                    orphanVersion = versions.stage(key("uncommitted"), prefs[versionKey] ?: 0)
                    prefs[versionKey] = orphanVersion
                    // Real on-disk write failure, not a fake DataStore: its parent becomes a file.
                    check(metadata.renameTo(backup))
                    metadata.writeText("test-only metadata write blocker")
                }
            }.exceptionOrNull()
            try {
                assertNotNull(failure)
                assertTrue(failure is IOException)
            } finally {
                if (metadata.isFile) check(metadata.delete())
                if (backup.isDirectory) check(backup.renameTo(metadata))
            }
            assertEquals(0L, owner.snapshot().revision)
            assertEquals(0L, owner.snapshot().value.homeSshRouteSettings.credentialVersion)
            assertEquals(key("old"), File(requireNotNull(versions.path(0))).readText())
            assertEquals(key("uncommitted"), File(requireNotNull(versions.path(orphanVersion))).readText())
        } finally { firstJob.cancelAndJoin() }

        val reopenedJob = SupervisorJob()
        try {
            val reopened = open(CoroutineScope(reopenedJob + Dispatchers.IO))
            assertEquals(0L, reopened.snapshot().revision)
            assertEquals(0L, reopened.snapshot().value.homeSshRouteSettings.credentialVersion)
            val committed = reopened.edit(epoch, 0) { prefs -> prefs[versionKey] = versions.stage(key("committed"), 0) }
            val selected = committed.value.homeSshRouteSettings.credentialVersion
            assertTrue(selected > orphanVersion)
            assertEquals(1L, committed.revision)
            assertEquals(key("committed"), File(requireNotNull(versions.path(selected))).readText())
            assertEquals(key("old"), legacy.readText())
            assertEquals(key("old"), File(requireNotNull(versions.path(0))).readText())
        } finally { reopenedJob.cancelAndJoin() }
    }

    @Test fun directorySyncFailureLeavesLegacyResolutionAndMetadataUnchanged() = fixture { root ->
        val credentials = File(root, "credentials").apply { check(mkdir()) }
        val legacy = File(credentials, "home-ssh-private-key").apply { writeText(key("old")) }
        val versions = AndroidSshCredentialVersions(credentials) { throw IOException("test-only sync failure") }
        assertTrue(runCatching { versions.stage(key("new"), 3) }.exceptionOrNull() is IOException)
        assertEquals(legacy.absolutePath, versions.path(3))
        assertEquals(key("old"), legacy.readText())
        assertFalse(File(credentials, "home-ssh-key-versions/versioned").exists())
    }

    private fun fixture(block: suspend (File) -> Unit) = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = Files.createTempDirectory(context.cacheDir.toPath(), "ssh-credential-native-").toFile()
        try { block(root) } finally { check(root.deleteRecursively()) }
    }
}
