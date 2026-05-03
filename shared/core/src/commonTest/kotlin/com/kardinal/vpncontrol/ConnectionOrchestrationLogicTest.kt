package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class ConnectionOrchestrationLogicTest {
    @Test
    fun standaloneConnectionMessagesUseStructuredStatuses() {
        assertEquals(
            ConnectionStatusMessages.startingConnection(AppMode.VPN),
            ConnectionOrchestrationLogic.preparingConnectionMessage(AppMode.VPN),
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartFailed(AppMode.PROXY_ONLY),
            ConnectionOrchestrationLogic.ensureSelectionFailureMessage(AppMode.PROXY_ONLY, null),
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
            ConnectionOrchestrationLogic.refreshSelectionStartedMessage(AppMode.VPN, "Germany"),
        )
        assertEquals(
            ConnectionStatusMessages.connectionStopFailed(AppMode.PROXY_ONLY),
            ConnectionOrchestrationLogic.connectionStopFailureMessage(AppMode.PROXY_ONLY, null),
        )
    }

    @Test
    fun retryAndCancellationMessagesUseStructuredStatuses() = runTest {
        val statuses = mutableListOf<String>()
        var attempts = 0

        ConnectionOrchestrationLogic.findBestProfileWithRetries(
            retryCount = 1,
            onRetryStatus = { statuses += it },
        ) {
            attempts += 1
            if (attempts == 1) {
                Result.failure(IllegalStateException("first failed"))
            } else {
                Result.success(Unit)
            }
        }

        assertEquals(BenchmarkStatusMessages.retryingBestLocationSearch(attempt = 2, total = 2), statuses.single())
        assertEquals(BenchmarkStatusMessages.locationSearchCancelled(), ConnectionOrchestrationLogic.refreshCancelledMessage())
    }

    @Test
    fun vpnPermissionPreconditionUsesStructuredStatus() {
        val message = ConnectionOrchestrationLogic.toggleStartPreconditionError(
            MainUiState(appMode = AppMode.VPN, hasVpnPermission = false),
        )

        assertEquals(BenchmarkStatusMessages.vpnPermissionRequired(), message)
    }

    @Test
    fun selectionFailureFallbacksUseStructuredStatuses() {
        val startTexts = ConnectionOrchestrationLogic.startSelectionFailureTexts(AppMode.VPN)
        val refreshTexts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(AppMode.PROXY_ONLY)

        assertEquals(
            ConnectionStatusMessages.connectionStartFailed(AppMode.VPN),
            startTexts.applyFailureFallback,
        )
        assertEquals(
            ConnectionStatusMessages.selectedLocationSaveFailed(),
            startTexts.persistFailureWithoutApplyFallback,
        )
        assertEquals(
            ConnectionStatusMessages.selectedLocationStartedSaveFailed(AppMode.VPN),
            startTexts.persistFailureAfterApplyFallback,
        )
        assertEquals(
            ConnectionStatusMessages.bestLocationStartFailed(AppMode.PROXY_ONLY),
            refreshTexts.applyFailureFallback,
        )
        assertEquals(
            ConnectionStatusMessages.bestLocationSaveFailed(),
            refreshTexts.persistFailureWithoutApplyFallback,
        )
        assertEquals(
            ConnectionStatusMessages.bestLocationStartedSaveFailed(AppMode.PROXY_ONLY),
            refreshTexts.persistFailureAfterApplyFallback,
        )
    }

    @Test
    fun explicitPlatformErrorsArePreserved() {
        assertEquals(
            "selection failed",
            ConnectionOrchestrationLogic.ensureSelectionFailureMessage(AppMode.VPN, "selection failed"),
        )
        assertEquals(
            "stop failed",
            ConnectionOrchestrationLogic.connectionStopFailureMessage(AppMode.PROXY_ONLY, "stop failed"),
        )
    }
}
