package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ControlModelsTest {
    @Test
    fun revisionRequiresControllerEpoch() {
        assertFailsWith<IllegalArgumentException> {
            ControlRequest("request", ControlCommand(ControlOperationId.SETTINGS_SET), ifRevision = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            ControlRequest("request", ControlCommand(ControlOperationId.SETTINGS_SET), controllerId = "owner", ifRevision = -1)
        }
    }

    @Test
    fun acceptanceRequiresOperationAndIsNotCompletion() {
        assertFailsWith<IllegalArgumentException> {
            ControlResult("owner", "request", ControlCode.ACCEPTED, 0)
        }
        assertFailsWith<IllegalArgumentException> {
            ControlResult("owner", "request", ControlCode.ACCEPTED, 0, final = false)
        }
        assertEquals(0, ControlResult("owner", "request", ControlCode.ACCEPTED, 0,
            final = false, operationId = "operation").exitCode)
    }

    @Test
    fun terminalOperationsHaveTruthfulResults() {
        assertFailsWith<IllegalArgumentException> {
            ControlOperation("id", "request", ControlOperationId.ON, ControlOperationPhase.SUCCEEDED, false)
        }
        assertFailsWith<IllegalArgumentException> {
            ControlOperation("id", "request", ControlOperationId.ON, ControlOperationPhase.SUCCEEDED, false,
                result = ControlResult("owner", "request", ControlCode.RUNTIME_FAILED, 0))
        }
    }

    @Test
    fun wireCodesAndExitCodesAreStable() {
        assertEquals(ControlCode.entries.size, ControlCode.entries.map { it.wireName }.distinct().size)
        assertEquals(130, ControlCode.CANCELLED.exitCode)
        assertEquals(2, ControlCode.TIMEOUT.exitCode)
        assertEquals(2, ControlCode.OUTCOME_UNKNOWN.exitCode)
        assertEquals(1, ControlCode.UNSUPPORTED.exitCode)
    }
}
