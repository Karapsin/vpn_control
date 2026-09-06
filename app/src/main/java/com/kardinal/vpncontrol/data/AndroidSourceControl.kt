package com.kardinal.vpncontrol.data

import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import com.kardinal.vpncontrol.model.*

/** Public source grammar; subscription IDs are identities, never names or fallback indexes. */
internal object AndroidSourceControl {
    fun clearsSelection(state: PersistedState, runtimeRunning: Boolean?): Boolean =
        runtimeRunning == false && RepositoryWorkflowService.shouldClearSelectionForSourceState(state)

    fun arguments(values: Map<String, ControlValue>): Map<String, ControlValue> {
        val source = (values["source"] as? ControlValue.Text)?.value
        val expected = if (source == "subscription") setOf("source", "subscription-id") else setOf("source")
        require(values.keys == expected && source in setOf("current-locations", "subscription", "all")) { "INVALID_ARGUMENT" }
        if (source == "subscription") require((values["subscription-id"] as? ControlValue.Text)?.value?.isNotBlank() == true) { "INVALID_ARGUMENT" }
        return values
    }

    fun target(state: PersistedState, values: Map<String, ControlValue>): Pair<ProfileSourceMode, String> {
        arguments(values)
        return when ((values.getValue("source") as ControlValue.Text).value) {
            "current-locations" -> ProfileSourceMode.CURRENT_LOCATIONS to state.activeSubscriptionId
            "all" -> {
                check(supportsAllSubscriptionsGroup(state.subscriptions)) { "NOT_FOUND" }
                ProfileSourceMode.SUBSCRIPTION to ALL_SUBSCRIPTIONS_ID
            }
            else -> {
                val id = (values.getValue("subscription-id") as ControlValue.Text).value
                check(state.subscriptions.any { it.id == id }) { "NOT_FOUND" }
                ProfileSourceMode.SUBSCRIPTION to id
            }
        }
    }

    fun result(state: PersistedState): Map<String, ControlValue> = mapOf(
        "mode" to ControlValue.Text(if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) "current-locations" else "subscription"),
        "subscriptionId" to if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) ControlValue.Text(state.activeSubscriptionId) else ControlValue.Null,
    )
}

/** Invalidates legacy file fallbacks in the same durable transaction as selection removal.
 * Files may belong to an active/prepared runtime: invalidation never deletes them. */
internal object AndroidSelectionCacheInvalidation {
    private val invalid = booleanPreferencesKey("selection_cache_invalidated")
    fun invalidate(preferences: MutablePreferences) { preferences[invalid] = true }
    fun selected(preferences: MutablePreferences, present: Boolean) {
        // Once invalidated, files are never authoritative again. A partial restore
        // can contain a new profile but no runtime config (or the reverse).
        // Committed nonblank components win independently in read().
        if (!present) invalidate(preferences)
    }
    fun read(preferences: Preferences, committed: String, fallback: () -> String?): String? =
        committed.takeIf { it.isNotBlank() } ?: if (preferences[invalid] == true) null else fallback()
}
