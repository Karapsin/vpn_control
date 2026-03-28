package com.kardinal.vpncontrol.data

import android.content.Context
import android.content.Intent
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.vpn.AndroidVpnService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class VpnManager(
    private val context: Context,
    private val storage: ProfileStorage,
) {
    suspend fun start(selection: ProfileSelection): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            storage.runtimeConfigFile().apply {
                parentFile?.mkdirs()
                writeText(selection.runtimeConfigJson)
            }
            if (selection.profile.rawLink.isNotBlank()) {
                storage.lastProfileFile().writeText(selection.profile.rawLink)
            }
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_START
            }
            context.startForegroundService(intent)
            Unit
        }
    }

    suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_STOP
            }
            context.startService(intent)
            Unit
        }
    }
}
