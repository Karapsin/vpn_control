package com.kardinal.vpncontrol.shared.storageapi

import com.kardinal.vpncontrol.model.ProfileSelection

interface VpnRuntimeController {
    suspend fun applySelection(selection: ProfileSelection): Result<Unit>

    suspend fun stop(): Result<Unit>
}
