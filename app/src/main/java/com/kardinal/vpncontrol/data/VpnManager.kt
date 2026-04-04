package com.kardinal.vpncontrol.data

import android.content.Context
import android.content.Intent
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.vpn.AndroidVpnService
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

class VpnManager(
    private val context: Context,
    private val storage: ProfileStorage,
) {
    suspend fun start(
        selection: ProfileSelection,
        rememberProfile: Boolean = true,
    ): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val initialStatus = storage.snapshot().statusMessage
            storage.runtimeConfigFile().apply {
                parentFile?.mkdirs()
                writeText(selection.runtimeConfigJson)
            }
            if (rememberProfile && selection.profile.rawLink.isNotBlank()) {
                storage.lastProfileFile().writeText(selection.profile.rawLink)
            }
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_START
            }
            try {
                context.startForegroundService(intent)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: "Failed to dispatch VPN start",
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStart(initialStatus)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: "Failed to start VPN",
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val initialStatus = storage.snapshot().statusMessage
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_STOP
            }
            try {
                context.startService(intent)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: "Failed to dispatch VPN stop",
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStop(initialStatus)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: "Failed to stop VPN",
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    private suspend fun waitForStart(initialStatus: String) {
        withTimeout(START_TIMEOUT_MILLIS) {
            while (true) {
                val state = storage.snapshot()
                if (state.isVpnRunning && state.statusMessage == STATUS_STARTED) {
                    return@withTimeout
                }
                if (!state.isVpnRunning &&
                    state.statusMessage.isNotBlank() &&
                    state.statusMessage != initialStatus
                ) {
                    error(state.statusMessage)
                }
                delay(POLL_INTERVAL_MILLIS)
            }
        }
    }

    private suspend fun waitForStop(initialStatus: String) {
        withTimeout(STOP_TIMEOUT_MILLIS) {
            while (true) {
                val state = storage.snapshot()
                if (!state.isVpnRunning &&
                    state.statusMessage.isNotBlank() &&
                    state.statusMessage != initialStatus
                ) {
                    return@withTimeout
                }
                delay(POLL_INTERVAL_MILLIS)
            }
        }
    }

    private companion object {
        const val STATUS_STARTED = "VPN started"
        const val POLL_INTERVAL_MILLIS = 100L
        const val START_TIMEOUT_MILLIS = 15_000L
        const val STOP_TIMEOUT_MILLIS = 10_000L
    }
}

class VpnCommandException(
    message: String,
    cause: Throwable? = null,
    val commandDispatched: Boolean,
) : IOException(message, cause)
