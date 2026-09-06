package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlSnapshotCodecTest {
    private val result = ControlResult("owner", "request", ControlCode.OK, 3, operationId = "operation",
        data = mapOf("validation.batch-size" to ControlValue.IntegerValue(7)))
    private val snapshot = ControlSnapshot("owner", 3, "selected", "active", AppMode.PROXY_ONLY,
        AppMode.VPN, "runtime", 123, true, listOf(ControlOperation("operation", "request",
            ControlOperationId.SETTINGS_SET, ControlOperationPhase.SUCCEEDED, false, result = result)))

    @Test fun roundTripsExplicitRuntimeAndOperationState() {
        assertEquals(snapshot, ControlSnapshotCodec.decode(ControlSnapshotCodec.encode(snapshot)))
        val stopped = snapshot.copy(activeLocationId = null, activeMode = null, runtimeId = null,
            runtimeStartedAt = null, runtimeRunning = false, operations = emptyList())
        assertEquals(stopped, ControlSnapshotCodec.decode(ControlSnapshotCodec.encode(stopped)))
    }

    @Test fun rejectsMalformedAndCrossOwnerOperationState() {
        val frame = ControlSnapshotCodec.encode(snapshot)
        for (invalid in listOf(
            frame.replace("\"configurationRevision\":3", "\"configurationRevision\":-1"),
            frame.replace("\"runtimeRunning\":true", "\"runtimeRunning\":\"true\""),
            frame.replace("\"configuredMode\":\"proxy-only\"", "\"configuredMode\":\"unknown\""),
            frame.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            frame.replaceFirst("{", "{\"privateUnexpectedField\":\"secret\","),
            ControlSnapshotCodec.encode(snapshot.copy(operations = snapshot.operations.map {
                it.copy(result = result.copy(controllerId = "another-owner"))
            })),
        )) {
            val error = assertFailsWith<ControlProtocolException> { ControlSnapshotCodec.decode(invalid) }
            assertFalse(error.message.orEmpty().contains("secret"))
        }
        assertFailsWith<ControlProtocolException> { ControlSnapshotCodec.decode(
            ControlSnapshotCodec.encode(snapshot.copy(operations = snapshot.operations + snapshot.operations))) }
    }
}
