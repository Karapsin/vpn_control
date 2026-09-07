package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue

internal suspend fun androidControlResourceBoundary(controllerId: String, requestId: String, operationId: String,
    action: suspend () -> ControlResult): ControlResult = try { action() }
    catch (_: OutOfMemoryError) { androidControlResourceFailure(controllerId, requestId, operationId) }

internal fun androidControlResourceFailure(controllerId: String, requestId: String, operationId: String,
    committedRevision: Long? = null): ControlResult = ControlResult(controllerId, requestId, ControlCode.RUNTIME_FAILED,
    committedRevision ?: 0, operationId = operationId,
    data = if (committedRevision != null) mapOf("configurationCommitted" to ControlValue.BooleanValue(true)) else emptyMap(),
    warnings = listOf("RESOURCE_EXHAUSTED", "PENDING_RESTART_STATE_UNAVAILABLE") +
        if (committedRevision != null) listOf("CONFIGURATION_COMMITTED", "POST_COMMIT_RESULT_UNAVAILABLE")
        else listOf("CONFIGURATION_REVISION_UNAVAILABLE", "CONFIGURATION_OUTCOME_UNKNOWN"))
