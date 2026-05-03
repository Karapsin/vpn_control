package com.kardinal.vpncontrol.data

import android.content.Context
import android.content.Intent
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.StatusMessages
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
            val initialState = storage.snapshot()
            val initialStatus = initialState.statusMessage
            val appMode = initialState.appMode
            storage.runtimeConfigFile().apply {
                parentFile?.mkdirs()
                writeText(selection.runtimeConfigJson)
            }
            if (rememberProfile) {
                if (selection.profile.rawLink.isNotBlank()) {
                    storage.lastProfileFile().writeText(selection.profile.rawLink)
                } else {
                    storage.lastProfileFile().delete()
                }
            }
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_START
            }
            try {
                context.startForegroundService(intent)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: StatusMessages.connectionStartFailed(appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStart(initialStatus, appMode)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: StatusMessages.connectionStartFailed(appMode),
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    suspend fun stop(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val initialState = storage.snapshot()
            val initialStatus = initialState.statusMessage
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_STOP
            }
            try {
                context.startService(intent)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: StatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStop(initialStatus)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: StatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    private suspend fun waitForStart(initialStatus: String) {
        waitForStart(initialStatus, storage.snapshot().appMode)
    }

    private suspend fun waitForStart(initialStatus: String, appMode: AppMode) {
        withTimeout(START_TIMEOUT_MILLIS) {
            while (true) {
                val state = storage.snapshot()
                if (state.isVpnRunning && state.statusMessage == startedStatus(appMode)) {
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
        const val POLL_INTERVAL_MILLIS = 100L
        const val START_TIMEOUT_MILLIS = 15_000L
        const val STOP_TIMEOUT_MILLIS = 10_000L

        fun startedStatus(appMode: AppMode): String {
            return StatusMessages.connectionStarted(appMode)
        }

    }
}

class VpnCommandException(
    message: String,
    cause: Throwable? = null,
    val commandDispatched: Boolean,
) : IOException(message, cause)
