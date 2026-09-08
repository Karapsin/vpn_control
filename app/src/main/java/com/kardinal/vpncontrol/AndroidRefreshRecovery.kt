package com.kardinal.vpncontrol

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Reconciles only this refresh's replacement; never derives a restart target from pending state. */
internal suspend fun recoverAndroidRefresh(point: AndroidRuntimeRestorePoint, attempted: Boolean,
    observation: () -> AndroidRuntimeObservation,
    stop: suspend (AndroidRuntimeObservation) -> Result<Unit>,
    restore: suspend (AndroidRuntimeRestorePoint, AndroidRuntimeObservation) -> Result<Unit>,
    capture: () -> AndroidRuntimeRestorePoint?,
): String = withContext(NonCancellable) {
    var current = observation()
    if (current == point.observation) return@withContext "RUNTIME_NOT_CHANGED"
    if (!attempted || current.knowledge == AndroidRuntimeKnowledge.UNKNOWN) return@withContext "RUNTIME_OUTCOME_UNKNOWN"
    if (current.knowledge == AndroidRuntimeKnowledge.RUNNING) {
        if (runCatching { stop(current).getOrThrow() }.isFailure) return@withContext "RUNTIME_OUTCOME_UNKNOWN"
        current = observation()
    }
    if (current.knowledge != AndroidRuntimeKnowledge.STOPPED) return@withContext "RUNTIME_OUTCOME_UNKNOWN"
    val recovered = runCatching { restore(point, current).getOrThrow() }
    val actual = capture()
    try {
    if (recovered.isSuccess && actual != null && actual.configuration == point.configuration && actual.runtimeJson == point.runtimeJson)
        "RUNTIME_RESTORED" else if (observation().knowledge == AndroidRuntimeKnowledge.STOPPED) "RUNTIME_STOPPED" else "RUNTIME_OUTCOME_UNKNOWN"
    } finally { actual?.close() }
}
