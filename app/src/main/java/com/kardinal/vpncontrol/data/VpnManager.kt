package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
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
            val initialState = storage.snapshot()
            val initialStatus = initialState.statusMessage
            val initialRuntimeStartSequence = initialState.runtimeStartSequence
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
                    message = error.message ?: ConnectionStatusMessages.connectionStartFailed(appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStart(
                    initialStatus = initialStatus,
                    initialRuntimeStartSequence = initialRuntimeStartSequence,
                )
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStartFailed(appMode),
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
                    message = error.message ?: ConnectionStatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                waitForStop(initialStatus)
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    private suspend fun waitForStart(
        initialStatus: String,
        initialRuntimeStartSequence: Long,
    ) {
        VpnStartWaiter.waitForStart(
            snapshot = storage::snapshot,
            initialStatus = initialStatus,
            initialRuntimeStartSequence = initialRuntimeStartSequence,
        )
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
        const val STOP_TIMEOUT_MILLIS = 10_000L
    }
}

internal object VpnStartWaiter {
    suspend fun waitForStart(
        snapshot: suspend () -> com.kardinal.vpncontrol.model.PersistedState,
        initialStatus: String,
        initialRuntimeStartSequence: Long,
        timeoutMillis: Long = 15_000L,
        pollIntervalMillis: Long = 100L,
        delayFn: suspend (Long) -> Unit = { delay(it) },
    ) {
        withTimeout(timeoutMillis) {
            while (true) {
                val state = snapshot()
                if (state.runtimeStartSequence > initialRuntimeStartSequence) {
                    return@withTimeout
                }
                if (!state.isVpnRunning &&
                    state.statusMessage.isNotBlank() &&
                    state.statusMessage != initialStatus
                ) {
                    error(state.statusMessage)
                }
                delayFn(pollIntervalMillis)
            }
        }
    }
}

class VpnCommandException(
    message: String,
    cause: Throwable? = null,
    val commandDispatched: Boolean,
) : IOException(message, cause)
