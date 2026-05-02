package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class ConnectionOrchestrationLogicTest {
    @Test
    fun standaloneConnectionMessagesUseStructuredStatuses() {
        val preparing = StatusMessages.decode(
            ConnectionOrchestrationLogic.preparingConnectionMessage(AppMode.VPN),
        )
        val prepareFailure = StatusMessages.decode(
            ConnectionOrchestrationLogic.ensureSelectionFailureMessage(AppMode.PROXY_ONLY, null),
        )
        val started = StatusMessages.decode(
            ConnectionOrchestrationLogic.refreshSelectionStartedMessage(AppMode.VPN, "Germany"),
        )
        val stopFailure = StatusMessages.decode(
            ConnectionOrchestrationLogic.connectionStopFailureMessage(AppMode.PROXY_ONLY, null),
        )

        assertEquals(StatusMessageKey.STARTING_CONNECTION, preparing?.key)
        assertEquals(listOf(AppMode.VPN.name), preparing?.args)
        assertEquals(StatusMessageKey.CONNECTION_START_FAILED, prepareFailure?.key)
        assertEquals(listOf(AppMode.PROXY_ONLY.name), prepareFailure?.args)
        assertEquals(StatusMessageKey.CONNECTION_STARTED_ON_TARGET, started?.key)
        assertEquals(listOf(AppMode.VPN.name, "Germany"), started?.args)
        assertEquals(StatusMessageKey.CONNECTION_STOP_FAILED, stopFailure?.key)
        assertEquals(listOf(AppMode.PROXY_ONLY.name), stopFailure?.args)
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

        val retry = StatusMessages.decode(statuses.single())
        val cancelled = StatusMessages.decode(ConnectionOrchestrationLogic.refreshCancelledMessage())

        assertEquals(StatusMessageKey.RETRYING_BEST_LOCATION_SEARCH, retry?.key)
        assertEquals(listOf("2", "2"), retry?.args)
        assertEquals(StatusMessageKey.LOCATION_SEARCH_CANCELLED, cancelled?.key)
    }

    @Test
    fun vpnPermissionPreconditionUsesStructuredStatus() {
        val message = ConnectionOrchestrationLogic.toggleStartPreconditionError(
            MainUiState(appMode = AppMode.VPN, hasVpnPermission = false),
        )

        assertEquals(StatusMessageKey.VPN_PERMISSION_REQUIRED, StatusMessages.decode(message.orEmpty())?.key)
    }

    @Test
    fun selectionFailureFallbacksUseStructuredStatuses() {
        val startTexts = ConnectionOrchestrationLogic.startSelectionFailureTexts(AppMode.VPN)
        val refreshTexts = ConnectionOrchestrationLogic.refreshSelectionFailureTexts(AppMode.PROXY_ONLY)

        assertEquals(
            StatusMessageKey.CONNECTION_START_FAILED,
            StatusMessages.decode(startTexts.applyFailureFallback)?.key,
        )
        assertEquals(
            StatusMessageKey.SELECTED_LOCATION_SAVE_FAILED,
            StatusMessages.decode(startTexts.persistFailureWithoutApplyFallback)?.key,
        )
        assertEquals(
            StatusMessageKey.SELECTED_LOCATION_STARTED_SAVE_FAILED,
            StatusMessages.decode(startTexts.persistFailureAfterApplyFallback)?.key,
        )
        assertEquals(
            StatusMessageKey.BEST_LOCATION_START_FAILED,
            StatusMessages.decode(refreshTexts.applyFailureFallback)?.key,
        )
        assertEquals(
            StatusMessageKey.BEST_LOCATION_SAVE_FAILED,
            StatusMessages.decode(refreshTexts.persistFailureWithoutApplyFallback)?.key,
        )
        assertEquals(
            StatusMessageKey.BEST_LOCATION_STARTED_SAVE_FAILED,
            StatusMessages.decode(refreshTexts.persistFailureAfterApplyFallback)?.key,
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
