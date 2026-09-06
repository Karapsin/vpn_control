package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperation
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlSnapshot
import kotlinx.coroutines.flow.StateFlow

/** IO adapters implement this boundary; GUI drafts never become authoritative snapshots. */
interface ControlSession {
    val snapshots: StateFlow<ControlSnapshot>
    suspend fun submit(request: ControlRequest): ControlResult
    suspend fun operation(id: String): ControlOperation?
    suspend fun cancelOperation(id: String): ControlResult
}
