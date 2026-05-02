package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
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
