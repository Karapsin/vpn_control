package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.VpnManager
import com.kardinal.vpncontrol.model.ProfileSelection

/** The recovery target is actual running A, never the pending selection. */
internal class AndroidFindBestRuntime private constructor(
    private val observer: AndroidRuntimeObserver,
    private val manager: VpnManager,
    private val services: AndroidRetainedRuntimeServices,
    private val eligible: () -> Boolean,
    private val original: AndroidRuntimeRestorePoint?,
    private var expected: AndroidRuntimeObservation,
    private var retained: AndroidRetainedRuntimeSession?,
) : AndroidFindBestControl.Runtime {
    override suspend fun start(selection: ProfileSelection): Result<Unit> {
        if (observer.state.value != expected) return Result.failure(IllegalStateException("RUNTIME_CHANGED"))
        val result = retained?.let { manager.startRetained(selection, it, expected) }
            ?: manager.startForControl(selection, eligible)
        expected = observer.state.value
        if (result.isSuccess && retained == null) {
            retained = services.acquire(expected)
            if (retained == null) return Result.failure(IllegalStateException("RUNTIME_RETENTION_UNAVAILABLE"))
        }
        return result
    }
    override suspend fun stopCandidate(): Result<Unit> {
        if (observer.state.value != expected) return Result.failure(IllegalStateException("RUNTIME_CHANGED"))
        val result = retained?.let { manager.stopRetained(expected, it) } ?: manager.stopPinnedForControl(expected)
        expected = observer.state.value
        return result
    }
    override suspend fun recover(): String {
        if (observer.state.value != expected) return "RUNTIME_OUTCOME_UNKNOWN"
        if (original == null) {
            if (expected.knowledge == AndroidRuntimeKnowledge.STOPPED) return "RUNTIME_NOT_CHANGED"
            if (expected.knowledge == AndroidRuntimeKnowledge.UNKNOWN) return "RUNTIME_OUTCOME_UNKNOWN"
            return if (stopCandidate().isSuccess) "RUNTIME_STOPPED" else "RUNTIME_OUTCOME_UNKNOWN"
        }
        val lease = retained ?: return "RUNTIME_OUTCOME_UNKNOWN"
        val outcome = recoverAndroidRefresh(original, true, { observer.state.value },
            { manager.stopRetained(it, lease) }, { point, stopped -> manager.restoreRetained(point, stopped, lease) },
            observer::captureRuntime).also { expected = observer.state.value }
        return if (outcome == "RUNTIME_NOT_CHANGED" && manager.restoreUnchangedRuntimeArtifacts(original).isFailure)
            "RUNTIME_ARTIFACT_RESTORE_FAILED" else outcome
    }
    override suspend fun release(): Result<Unit> = retained?.release() ?: Result.success(Unit)
    companion object {
        suspend fun open(observer: AndroidRuntimeObserver, manager: VpnManager,
            services: AndroidRetainedRuntimeServices, eligible: () -> Boolean): AndroidFindBestRuntime {
            val observed = observer.state.value
            check(observed.knowledge != AndroidRuntimeKnowledge.UNKNOWN) { "RUNTIME_OUTCOME_UNKNOWN" }
            val point = observer.captureRuntime()
            val retained = if (observed.knowledge == AndroidRuntimeKnowledge.RUNNING) {
                check(point != null && point.observation == observed) { "RUNTIME_OUTCOME_UNKNOWN" }
                requireNotNull(services.acquire(observed)) { "RUNTIME_RETENTION_UNAVAILABLE" }
            } else null
            return AndroidFindBestRuntime(observer, manager, services, eligible, point, observed, retained)
        }
    }
}
