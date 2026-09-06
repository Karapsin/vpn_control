package com.kardinal.vpncontrol.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlConfigurationIdentity
import com.kardinal.vpncontrol.model.PersistedState
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.util.UUID

/** One process epoch shared even by legacy callers constructing their own ProfileStorage facade. */
internal object AndroidConfigurationEpoch { val id: String = UUID.randomUUID().toString() }

/** Revision and values commit together inside DataStore's existing all-writer transaction. */
internal class AndroidConfigurationStore(
    private val store: DataStore<Preferences>,
    private val decode: (Preferences) -> PersistedState,
    val controllerId: String = AndroidConfigurationEpoch.id,
) {
    val state = store.data.map(::committed)

    suspend fun snapshot(): ControlCommitted<PersistedState> = committed(store.data.first())

    suspend fun edit(
        expectedControllerId: String? = null,
        expectedRevision: Long? = null,
        transform: suspend (MutablePreferences) -> Unit,
    ): ControlCommitted<PersistedState> {
        require(expectedRevision == null || expectedControllerId != null) { "INVALID_ARGUMENT" }
        val committedPreferences = store.edit { preferences ->
            val prior = committed(preferences)
            check(expectedControllerId == null || expectedControllerId == controllerId) { "CONFLICT" }
            check(expectedRevision == null || expectedRevision == prior.revision) { "CONFLICT" }
            val before = ControlConfigurationIdentity.of(prior.value)
            transform(preferences)
            val changed = before != ControlConfigurationIdentity.of(decode(preferences))
            check(!changed || prior.revision < Long.MAX_VALUE) { "CONFLICT" }
            preferences[EPOCH] = controllerId
            preferences[REVISION] = prior.revision + if (changed) 1 else 0
        }
        return committed(committedPreferences)
    }

    private fun committed(preferences: Preferences) = ControlCommitted(
        controllerId,
        if (preferences[EPOCH] == controllerId) (preferences[REVISION] ?: 0L).also {
            check(it >= 0) { "INCOMPATIBLE_PROTOCOL" }
        } else 0,
        decode(preferences),
    )

    private companion object {
        val EPOCH = stringPreferencesKey("control_configuration_epoch")
        val REVISION = longPreferencesKey("control_configuration_revision")
    }
}
