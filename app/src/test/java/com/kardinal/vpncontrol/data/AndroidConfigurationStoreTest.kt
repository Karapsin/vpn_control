package com.kardinal.vpncontrol.data

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.edit
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AndroidConfigurationStoreTest {
    @get:Rule val temporary = TemporaryFolder()
    private val mode = stringPreferencesKey("app_mode")
    private val status = stringPreferencesKey("status_message")
    private val running = booleanPreferencesKey("is_vpn_running")
    private val keyVersion = longPreferencesKey("home_ssh_credential_version")

    @Test fun stagedKeyFailureKeepsOldIdentityAndStaleGuardRunsBeforeFilesystemEffects() = fixture { dataStore ->
        val root = temporary.newFolder()
        val old = "-----BEGIN PRIVATE KEY-----\nOLD\n-----END PRIVATE KEY-----\n"
        val fresh = "-----BEGIN PRIVATE KEY-----\nNEW\n-----END PRIVATE KEY-----\n"
        File(root, "home-ssh-private-key").writeText(old)
        val keys = AndroidSshCredentialVersions(root)
        val owner = wrapper(dataStore)
        var staged = -1L
        assertTrue(runCatching {
            owner.edit("owner", 0) { prefs ->
                staged = keys.stage(fresh, prefs[keyVersion] ?: 0)
                prefs[keyVersion] = staged
                error("fixture metadata failure")
            }
        }.isFailure)
        assertEquals(0, owner.snapshot().revision)
        assertEquals(0, owner.snapshot().value.homeSshRouteSettings.credentialVersion)
        assertEquals(old, File(keys.path(0)!!).readText())
        val committed = owner.edit("owner", 0) { prefs -> prefs[keyVersion] = keys.stage(fresh, 0) }
        assertTrue(committed.value.homeSshRouteSettings.credentialVersion > staged)
        assertEquals(1, committed.revision)
        val entries = root.walkTopDown().count()
        assertEquals("CONFLICT", runCatching {
            owner.edit("owner", 0) { prefs -> prefs[keyVersion] = keys.stage(old, 0) }
        }.exceptionOrNull()?.message)
        assertEquals(entries, root.walkTopDown().count())
        assertEquals(fresh, File(keys.path(committed.value.homeSshRouteSettings.credentialVersion)!!).readText())
    }

    @Test fun legacyWriterChangesNoOpsAndTelemetryShareOneAtomicRevision() = fixture { dataStore ->
        val gui = wrapper(dataStore)
        val provider = wrapper(dataStore)
        assertEquals(0, provider.snapshot().revision)
        gui.edit { it[mode] = AppMode.PROXY_ONLY.name }
        assertEquals(1, provider.snapshot().revision)
        gui.edit { it[mode] = AppMode.PROXY_ONLY.name }
        gui.edit { it[status] = "New telemetry"; it[running] = true }
        assertEquals(1, provider.snapshot().revision)
        assertTrue(provider.snapshot().value.isVpnRunning)
    }

    @Test fun staleEpochOrRevisionRejectsBeforeProposalIncludingNoOp() = fixture { dataStore ->
        val owner = wrapper(dataStore)
        owner.edit { it[mode] = AppMode.PROXY_ONLY.name }
        var effects = 0
        for ((epoch, revision) in listOf("old-owner" to 1L, "owner" to 0L)) {
            val result = runCatching { owner.edit(epoch, revision) { effects++; it[mode] = AppMode.PROXY_ONLY.name } }
            assertEquals("CONFLICT", result.exceptionOrNull()?.message)
        }
        assertEquals(0, effects)
        assertEquals(1, owner.snapshot().revision)
    }

    @Test fun competingGuardedWritesHaveExactlyOneWinner() = fixture { dataStore ->
        val owner = wrapper(dataStore)
        val first = async { runCatching { owner.edit("owner", 0) { it[mode] = AppMode.PROXY_ONLY.name } } }
        val second = async { runCatching { wrapper(dataStore).edit("owner", 0) { it[mode] = AppMode.PROXY_ONLY.name } } }
        assertEquals(1, listOf(first.await(), second.await()).count { it.isSuccess })
        assertEquals(1, owner.snapshot().revision)
    }

    @Test fun failedTransactionPublishesNeitherConfigurationNorRevision() = fixture { dataStore ->
        val owner = wrapper(dataStore)
        val failed = runCatching {
            owner.edit { it[mode] = AppMode.PROXY_ONLY.name; error("fixture failure") }
        }
        assertTrue(failed.isFailure)
        assertEquals(0, owner.snapshot().revision)
        assertEquals(AppMode.VPN, owner.snapshot().value.appMode)
    }

    @Test fun newProcessEpochStartsAtZeroWithoutLosingCommittedData() = fixture { dataStore ->
        wrapper(dataStore).edit { it[mode] = AppMode.PROXY_ONLY.name }
        val newProcess = wrapper(dataStore, "new-owner")
        assertEquals(0, newProcess.snapshot().revision)
        assertEquals(AppMode.PROXY_ONLY, newProcess.snapshot().value.appMode)
        newProcess.edit { it[status] = "telemetry" }
        assertEquals(0, newProcess.snapshot().revision)
        newProcess.edit { it[mode] = AppMode.VPN.name }
        assertEquals(1, newProcess.snapshot().revision)
    }

    @Test fun revisionOverflowRejectsConfigurationButStillAllowsTelemetry() = fixture { dataStore ->
        dataStore.edit {
            it[stringPreferencesKey("control_configuration_epoch")] = "owner"
            it[longPreferencesKey("control_configuration_revision")] = Long.MAX_VALUE
        }
        val owner = wrapper(dataStore)
        assertEquals("CONFLICT", runCatching { owner.edit { it[mode] = AppMode.PROXY_ONLY.name } }.exceptionOrNull()?.message)
        assertEquals(AppMode.VPN, owner.snapshot().value.appMode)
        owner.edit { it[status] = "telemetry" }
        assertEquals(Long.MAX_VALUE, owner.snapshot().revision)
    }

    private fun wrapper(store: androidx.datastore.core.DataStore<androidx.datastore.preferences.core.Preferences>, epoch: String = "owner") =
        AndroidConfigurationStore(store, { preferences -> PersistedState(
            appMode = preferences[mode]?.let(AppMode::valueOf) ?: AppMode.VPN,
            statusMessage = preferences[status].orEmpty(), isVpnRunning = preferences[running] ?: false,
            homeSshRouteSettings = com.kardinal.vpncontrol.model.HomeSshRouteSettings(credentialVersion = preferences[keyVersion] ?: 0),
        ) }, epoch)

    private fun fixture(block: suspend CoroutineScope.(androidx.datastore.core.DataStore<androidx.datastore.preferences.core.Preferences>) -> Unit) = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        try {
            val file = File(temporary.newFolder(), "configuration.preferences_pb")
            val store = PreferenceDataStoreFactory.create(scope = scope) { file }
            block(store)
        } finally {
            scope.cancel()
        }
    }
}
