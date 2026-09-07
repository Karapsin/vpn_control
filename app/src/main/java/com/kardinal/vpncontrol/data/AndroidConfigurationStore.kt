package com.kardinal.vpncontrol.data

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
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
    private val snapshotLock = Any()
    private var cachedPreferences: Preferences? = null
    private var cachedValue: PersistedState? = null
    val state = store.data.map(::committed)

    suspend fun snapshot(): ControlCommitted<PersistedState> = committed(store.data.first())

    suspend fun edit(
        expectedControllerId: String? = null,
        expectedRevision: Long? = null,
        transform: suspend (MutablePreferences) -> Unit,
    ): ControlCommitted<PersistedState> = editProjected(expectedControllerId, expectedRevision) { preferences, _ -> transform(preferences) }

    suspend fun editProjected(
        expectedControllerId: String? = null,
        expectedRevision: Long? = null,
        transform: suspend (MutablePreferences, PersistedState) -> Unit,
    ): ControlCommitted<PersistedState> {
        require(expectedRevision == null || expectedControllerId != null) { "INVALID_ARGUMENT" }
        val committedPreferences = store.updateData { existing ->
            val preferences = existing.toMutablePreferences()
            // Only published immutable inputs may enter the identity cache.
            val prior = committed(existing)
            check(expectedControllerId == null || expectedControllerId == controllerId) { "CONFLICT" }
            check(expectedRevision == null || expectedRevision == prior.revision) { "CONFLICT" }
            val before = ControlConfigurationIdentity.of(prior.value)
            transform(preferences, prior.value)
            val changed = preferences != existing && before != ControlConfigurationIdentity.of(decode(preferences))
            check(!changed || prior.revision < Long.MAX_VALUE) { "CONFLICT" }
            preferences[EPOCH] = controllerId
            preferences[REVISION] = prior.revision + if (changed) 1 else 0
            if (preferences == existing) existing else preferences.toPreferences()
        }
        return committed(committedPreferences)
    }

    private fun committed(preferences: Preferences): ControlCommitted<PersistedState> = synchronized(snapshotLock) {
        val value = if (cachedPreferences === preferences) requireNotNull(cachedValue) else {
            decode(preferences).also { decoded -> cachedPreferences = preferences; cachedValue = decoded }
        }
        ControlCommitted(controllerId,
            if (preferences[EPOCH] == controllerId) (preferences[REVISION] ?: 0L).also {
                check(it >= 0) { "INCOMPATIBLE_PROTOCOL" }
            } else 0, value)
    }

    private companion object {
        val EPOCH = stringPreferencesKey("control_configuration_epoch")
        val REVISION = longPreferencesKey("control_configuration_revision")
    }
}
