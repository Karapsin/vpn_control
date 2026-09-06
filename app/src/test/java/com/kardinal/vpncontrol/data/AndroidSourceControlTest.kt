package com.kardinal.vpncontrol.data

import androidx.datastore.preferences.core.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test
import java.nio.file.Files

class AndroidSourceControlTest {
    private val subscriptions = listOf(SubscriptionSource(id = "one", url = "https://private-one.invalid"),
        SubscriptionSource(id = "two", url = "https://private-two.invalid"))
    private fun args(source: String, id: String? = null) = mapOf("source" to ControlValue.Text(source)) +
        (id?.let { mapOf("subscription-id" to ControlValue.Text(it)) } ?: emptyMap())

    @Test fun exactIdsAndAllEligibilityNeverFallBackToFirstSubscription() {
        val state = PersistedState(subscriptions = subscriptions, activeSubscriptionId = "one")
        assertEquals(ProfileSourceMode.SUBSCRIPTION to "two", AndroidSourceControl.target(state, args("subscription", "two")))
        assertEquals(ProfileSourceMode.CURRENT_LOCATIONS to "one", AndroidSourceControl.target(state, args("current-locations")))
        assertEquals(ProfileSourceMode.SUBSCRIPTION to ALL_SUBSCRIPTIONS_ID, AndroidSourceControl.target(state, args("all")))
        assertEquals("NOT_FOUND", runCatching { AndroidSourceControl.target(state, args("subscription", "2")) }.exceptionOrNull()?.message)
        assertEquals("NOT_FOUND", runCatching { AndroidSourceControl.target(state.copy(subscriptions = subscriptions.take(1)), args("all")) }.exceptionOrNull()?.message)
        for (invalid in listOf(args("unknown"), args("all", "two"), args("subscription"), args("subscription", " ")))
            assertEquals("INVALID_ARGUMENT", runCatching { AndroidSourceControl.arguments(invalid) }.exceptionOrNull()?.message)
        assertFalse(AndroidSourceControl.result(state).toString().contains("private-one"))
    }

    @Test fun sourceChangePreservesRunningSelectionAndClearsOnlyIneligibleStoppedSelection() {
        val state = PersistedState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION, subscriptions = subscriptions,
            activeSubscriptionId = "two", selectedProfileName = "selected", selectedProfileRawLink = "socks://old.invalid:1080",
            selectedProfileSourceUrl = subscriptions.first().url, runtimeConfigJson = "ACTIVE_CONFIG")
        assertTrue(AndroidSourceControl.clearsSelection(state, runtimeRunning = false))
        assertFalse(AndroidSourceControl.clearsSelection(state, runtimeRunning = true))
        assertFalse(AndroidSourceControl.clearsSelection(state.copy(isVpnRunning = false), runtimeRunning = null))
        assertTrue(AndroidSourceControl.clearsSelection(state.copy(isVpnRunning = true), runtimeRunning = false))
        assertFalse(AndroidSourceControl.clearsSelection(state.copy(activeSubscriptionId = "one"), runtimeRunning = false))
        assertFalse(AndroidSourceControl.clearsSelection(state.copy(selectedProfileName = ""), runtimeRunning = false))
        assertEquals("ACTIVE_CONFIG", state.runtimeConfigJson)
    }

    @Test fun failedCommitKeepsCacheAndDurableInvalidationSurvivesRestartUntilNewSelection() = runBlocking {
        val root = Files.createTempDirectory("source-cache").toFile()
        val file = root.resolve("state.preferences_pb")
        val cached = root.resolve("runtime.json").apply { writeText("OLD_RUNTIME") }
        val selected = stringPreferencesKey("selected_profile_raw_link")
        var scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        fun store() = PreferenceDataStoreFactory.create(scope = scope) { file }
        try {
            var preferences = store()
            fun owner() = AndroidConfigurationStore(preferences, { PersistedState(selectedProfileRawLink = it[selected].orEmpty()) }, "owner")
            owner().edit { it[selected] = "OLD_SELECTION" }
            assertTrue(runCatching { owner().edit("owner", 1) {
                it.remove(selected); AndroidSelectionCacheInvalidation.invalidate(it); error("COMMIT_FAILURE")
            } }.isFailure)
            assertEquals(1L, owner().snapshot().revision)
            assertEquals("OLD_SELECTION", AndroidSelectionCacheInvalidation.read(preferences.data.first(), preferences.data.first()[selected].orEmpty()) { cached.readText() })
            assertEquals("OLD_RUNTIME", cached.readText())
            var effects = 0
            for ((epoch, revision) in listOf("old-owner" to 1L, "owner" to 0L)) {
                assertEquals("CONFLICT", runCatching { owner().edit(epoch, revision) { effects++; AndroidSelectionCacheInvalidation.invalidate(it) } }.exceptionOrNull()?.message)
            }
            assertEquals(0, effects)
            owner().edit("owner", 1) { it.remove(selected); AndroidSelectionCacheInvalidation.invalidate(it) }
            scope.coroutineContext[Job]!!.cancelAndJoin()
            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            preferences = store()
            assertNull(AndroidSelectionCacheInvalidation.read(preferences.data.first(), "") { cached.readText() })
            assertEquals("OLD_RUNTIME", cached.readText())
            owner().edit { it[selected] = "NEW_SELECTION"; AndroidSelectionCacheInvalidation.selected(it, true) }
            assertEquals("NEW_SELECTION", AndroidSelectionCacheInvalidation.read(preferences.data.first(), preferences.data.first()[selected].orEmpty()) { cached.readText() })
            assertNull("A new profile with no config must not revive an unrelated runtime file",
                AndroidSelectionCacheInvalidation.read(preferences.data.first(), "") { cached.readText() })
            owner().edit { it.remove(selected); AndroidSelectionCacheInvalidation.selected(it, true) }
            assertNull("A restored JSON-only profile must not revive the old raw-link file",
                AndroidSelectionCacheInvalidation.read(preferences.data.first(), "") { "OLD_RAW_LINK" })
            assertEquals("NEW_RUNTIME", AndroidSelectionCacheInvalidation.read(preferences.data.first(), "NEW_RUNTIME") { cached.readText() })
        } finally { scope.coroutineContext[Job]!!.cancelAndJoin(); root.deleteRecursively() }
    }
}
