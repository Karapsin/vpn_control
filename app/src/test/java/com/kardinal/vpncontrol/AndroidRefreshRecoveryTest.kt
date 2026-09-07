package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidRefreshRecoveryTest {
    @Test fun recoveryRestoresPinnedActualAAndNeverRehydratesPendingB() = runTest {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val configuration = ControlRuntimeConfiguration.committed(MainUiState().copy(selectedProfileRawLink = "actual-A"))
        observer.started(Any(), AppMode.VPN, "actual-A-json", configuration)
        val point = requireNotNull(observer.captureRuntime())
        observer.started(Any(), AppMode.VPN, "replacement-json", configuration.copy(locationReference = "replacement"))
        var restores = 0
        val result = recoverAndroidRefresh(point, true, { observer.state.value }, {
            observer.resetCompleted(true); Result.success(Unit)
        }, { actual, _ ->
            restores++; assertSame(point, actual)
            observer.started(Any(), actual.configuration.mode, actual.runtimeJson, actual.configuration)
            Result.success(Unit)
        }, observer::captureRuntime)
        assertEquals("RUNTIME_RESTORED", result); assertEquals(1, restores)
        assertEquals("actual-A", observer.captureRuntime()?.configuration?.locationReference)
    }
    @Test fun uncertainStopNeverBlindlyRestartsAndConfirmedStoppedRestoreFailureIsExplicit() = runTest {
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val config = ControlRuntimeConfiguration.committed(MainUiState())
        observer.started(Any(), AppMode.VPN, "A", config)
        val point = requireNotNull(observer.captureRuntime())
        observer.started(Any(), AppMode.VPN, "replacement", config)
        var restores = 0
        assertEquals("RUNTIME_OUTCOME_UNKNOWN", recoverAndroidRefresh(point, true, { observer.state.value }, {
            observer.resetCompleted(false); Result.failure(IllegalStateException("unknown"))
        }, { _, _ -> restores++; Result.success(Unit) }, observer::captureRuntime))
        assertEquals(0, restores)
        val stopped = AndroidRuntimeObserver(initiallyStopped = true)
        assertEquals("RUNTIME_STOPPED", recoverAndroidRefresh(point, true, { stopped.state.value }, { error("Already off") },
            { _, _ -> Result.failure(IllegalStateException("denied")) }, stopped::captureRuntime))
    }
}
