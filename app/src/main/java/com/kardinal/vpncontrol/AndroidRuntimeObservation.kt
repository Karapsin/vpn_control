package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import java.security.MessageDigest
import java.security.SecureRandom
import java.nio.ByteBuffer
import java.util.UUID
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class AndroidRuntimeKnowledge { UNKNOWN, RUNNING, STOPPED }

internal data class AndroidControlStatus(val data: Map<String, ControlValue>, val pending: Boolean?, val authoritative: Boolean)

/** Only actual service observations. Never reconstructed from persisted selection/settings. */
internal data class AndroidRuntimeObservation(
    val knowledge: AndroidRuntimeKnowledge = AndroidRuntimeKnowledge.UNKNOWN,
    val runtimeId: String? = null,
    val configurationId: String? = null,
    val activeMode: AppMode? = null,
    val startedAtEpochMillis: Long? = null,
    val stoppedAtEpochMillis: Long? = null,
    internal val generation: String = UUID.randomUUID().toString(),
) {
    fun applyKnownState(state: MainUiState): MainUiState = when (knowledge) {
        AndroidRuntimeKnowledge.UNKNOWN -> state
        AndroidRuntimeKnowledge.RUNNING -> state.copy(isVpnRunning = true, sessionStartedAtEpochMillis = requireNotNull(startedAtEpochMillis))
        AndroidRuntimeKnowledge.STOPPED -> state.copy(isVpnRunning = false,
            sessionStoppedAtEpochMillis = stoppedAtEpochMillis ?: state.sessionStoppedAtEpochMillis)
    }

    // startedAtEpochMillis/stoppedAtEpochMillis remain durable historical events.
    // runtimeStartedAtEpochMillis identifies only the currently observed native runtime;
    // it may differ after restart and is null when off/unknown. Elapsed uses this live time.
    fun stats(historical: Map<String, ControlValue>, nowMillis: Long): Map<String, ControlValue> = historical + mapOf(
        "running" to when (knowledge) {
            AndroidRuntimeKnowledge.UNKNOWN -> ControlValue.Null
            AndroidRuntimeKnowledge.RUNNING -> ControlValue.BooleanValue(true)
            AndroidRuntimeKnowledge.STOPPED -> ControlValue.BooleanValue(false)
        },
        "elapsedMillis" to if (startedAtEpochMillis != null && knowledge == AndroidRuntimeKnowledge.RUNNING)
            ControlValue.IntegerValue((nowMillis - startedAtEpochMillis).coerceAtLeast(0)) else ControlValue.Null,
        "runtimeId" to (runtimeId?.let(ControlValue::Text) ?: ControlValue.Null),
        "activeConfigurationId" to (configurationId?.let(ControlValue::Text) ?: ControlValue.Null),
        "activeMode" to (activeMode?.let { ControlValue.Text(if (it == AppMode.VPN) "vpn" else "proxy-only") } ?: ControlValue.Null),
        "runtimeStartedAtEpochMillis" to (startedAtEpochMillis?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
        "runtimeObservation" to ControlValue.Text(knowledge.name.lowercase()),
    )
}

/** Application lifetime; a recreated GUI observes the same immutable descriptor. */
internal class AndroidRuntimeObserver(
    private val clockMillis: () -> Long = System::currentTimeMillis,
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
    initiallyStopped: Boolean = false,
) {
    private val salt = ByteArray(32).also(SecureRandom()::nextBytes)
    private var activeHandle: Any? = null
    private var activeConfiguration: ControlRuntimeConfiguration? = null
    private var activeRuntimeJson: String? = null
    private var cleanupUncertain = false
    private val mutableState = MutableStateFlow(AndroidRuntimeObservation(
        if (initiallyStopped) AndroidRuntimeKnowledge.STOPPED else AndroidRuntimeKnowledge.UNKNOWN,
    ))
    val state = mutableState.asStateFlow()

    @Synchronized fun started(handle: Any, mode: AppMode, actualRuntimeConfig: String, prepared: ControlRuntimeConfiguration? = null) {
        if (cleanupUncertain) return
        if (activeHandle === handle) return // Observing an already-started native handle is a no-op.
        val configurationId = MessageDigest.getInstance("SHA-256").run {
            update(salt)
            digest(actualRuntimeConfig.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
        }
        activeHandle = handle
        activeConfiguration = prepared?.takeIf { it.mode == mode }
        activeRuntimeJson = actualRuntimeConfig
        mutableState.value = AndroidRuntimeObservation(
            knowledge = AndroidRuntimeKnowledge.RUNNING, runtimeId = idGenerator(),
            configurationId = configurationId, activeMode = mode, startedAtEpochMillis = clockMillis(),
        )
    }

    @Synchronized fun resetCompleted(cleanupSucceeded: Boolean) {
        activeHandle = null
        activeConfiguration = null
        activeRuntimeJson = null
        // Existing native cleanup forgets handles after a close exception. Do not claim off
        // or a single known runtime afterward; only a new process can remove that uncertainty.
        cleanupUncertain = cleanupUncertain || !cleanupSucceeded
        mutableState.value = if (cleanupUncertain) AndroidRuntimeObservation() else {
            if (mutableState.value.knowledge == AndroidRuntimeKnowledge.STOPPED) return
            AndroidRuntimeObservation(AndroidRuntimeKnowledge.STOPPED, stoppedAtEpochMillis = clockMillis())
        }
    }

    @Synchronized fun hasAuthoritativeConfiguration(): Boolean =
        mutableState.value.knowledge == AndroidRuntimeKnowledge.STOPPED ||
            mutableState.value.knowledge == AndroidRuntimeKnowledge.RUNNING && activeConfiguration != null

    /** Private owner-only recovery material; never projected into status, logs or persistence. */
    @Synchronized fun captureRuntime(): AndroidRuntimeRestorePoint? {
        val observation = mutableState.value
        if (observation.knowledge != AndroidRuntimeKnowledge.RUNNING) return null
        return AndroidRuntimeRestorePoint(observation, activeRuntimeJson ?: return null, activeConfiguration ?: return null)
    }

    @Synchronized fun pendingRestart(committed: PersistedState): Boolean? = when (mutableState.value.knowledge) {
        AndroidRuntimeKnowledge.UNKNOWN -> null
        AndroidRuntimeKnowledge.STOPPED -> false
        AndroidRuntimeKnowledge.RUNNING -> activeConfiguration?.hasPendingChanges(
            MainUiStateProjector.mergePersistedState(MainUiState(), committed),
        )
    }

    /** One monitor captures actual runtime identity, its prepared inputs and pending comparison. */
    @Synchronized fun locationVisualState(committed: PersistedState): AndroidLocationVisualState = AndroidLocationVisualState(
        activeConfiguration?.takeIf { mutableState.value.knowledge == AndroidRuntimeKnowledge.RUNNING }?.let {
            androidLocationVisualKey(it.locationReference, it.sourceReference)
        }, pendingRestart(committed),
    )

    @Synchronized fun controlStatus(committed: PersistedState): AndroidControlStatus {
        val observed = mutableState.value
        val selected = ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), committed))
        val pending = pendingRestart(committed)
        fun identity(configuration: ControlRuntimeConfiguration?): ControlValue {
            if (configuration == null || configuration.locationReference.isBlank()) return ControlValue.Null
            val source = configuration.sourceReference.toByteArray(Charsets.UTF_8)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(salt)
            digest.update(ByteBuffer.allocate(4).putInt(source.size).array())
            digest.update(source)
            return ControlValue.Text(digest.digest(configuration.locationReference.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) })
        }
        fun mode(value: AppMode?) = value?.let { ControlValue.Text(if (it == AppMode.VPN) "vpn" else "proxy-only") } ?: ControlValue.Null
        return AndroidControlStatus(mapOf(
            "runtimeRunning" to when (observed.knowledge) {
                AndroidRuntimeKnowledge.UNKNOWN -> ControlValue.Null
                else -> ControlValue.BooleanValue(observed.knowledge == AndroidRuntimeKnowledge.RUNNING)
            },
            "selectedLocationId" to identity(selected),
            "activeLocationId" to identity(activeConfiguration),
            "configuredMode" to mode(selected.mode),
            "activeMode" to mode(observed.activeMode),
            "runtimeId" to (observed.runtimeId?.let(ControlValue::Text) ?: ControlValue.Null),
            "runtimeStartedAt" to (observed.startedAtEpochMillis?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
            "restartRequired" to (pending?.let(ControlValue::BooleanValue) ?: ControlValue.Null),
            "runtimeObservation" to ControlValue.Text(observed.knowledge.name.lowercase()),
        ), pending, observed.knowledge != AndroidRuntimeKnowledge.UNKNOWN && pending != null)
    }
}

internal class AndroidRuntimeRestorePoint(val observation: AndroidRuntimeObservation,
    val runtimeJson: String, val configuration: ControlRuntimeConfiguration) {
    override fun toString(): String = "AndroidRuntimeRestorePoint(<redacted>)"
}
