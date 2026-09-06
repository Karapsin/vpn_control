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
    ): Result<Unit> = startAndAwait(selection, rememberProfile, 15_000L, null)

    internal suspend fun startForControl(selection: ProfileSelection, eligible: () -> Boolean): Result<Unit> =
        startAndAwait(selection, true, 300_000L, eligible)

    private suspend fun startAndAwait(selection: ProfileSelection, rememberProfile: Boolean, timeoutMillis: Long,
        eligible: (() -> Boolean)?): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            if (eligible != null) withContext(Dispatchers.Main.immediate) { check(eligible()) { "INTERACTION_REQUIRED" } }
            val initialState = storage.snapshot()
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
            val prepared = com.kardinal.vpncontrol.AndroidApplicationOwner.get(context).preparedConnections
            val preparedId = prepared.dispatch(selection)
            val commands = com.kardinal.vpncontrol.AndroidApplicationOwner.get(context).runtimeCommands
            val ticket = commands.register(com.kardinal.vpncontrol.AndroidRuntimeAction.START, selection.runtimeConfigJson)
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_START
                putExtra(AndroidVpnService.EXTRA_PREPARED_CONNECTION_ID, preparedId)
                putExtra(AndroidVpnService.EXTRA_COMMAND_ID, ticket.id)
            }
            try {
                withContext(Dispatchers.Main.immediate) {
                    check(eligible == null || eligible()) { "INTERACTION_REQUIRED" }
                    context.startForegroundService(intent)
                }
            } catch (error: Throwable) {
                prepared.discard(preparedId)
                commands.discard(ticket)
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStartFailed(appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                commands.await(ticket, timeoutMillis).getOrThrow()
            } catch (error: Throwable) {
                prepared.discard(preparedId)
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStartFailed(appMode),
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    suspend fun stop(): Result<Unit> = stopAndAwait(STOP_TIMEOUT_MILLIS)

    // Provider wait cancellation never cancels this owner operation. Keep admission
    // while waiting for actual cleanup, up to the bounded native receipt retention.
    internal suspend fun stopForControl(): Result<Unit> = stopAndAwait(300_000L)

    private suspend fun stopAndAwait(timeoutMillis: Long): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching {
            val initialState = storage.snapshot()
            val commands = com.kardinal.vpncontrol.AndroidApplicationOwner.get(context).runtimeCommands
            val ticket = commands.register(com.kardinal.vpncontrol.AndroidRuntimeAction.STOP)
            val intent = Intent(context, AndroidVpnService::class.java).apply {
                action = AndroidVpnService.ACTION_STOP
                putExtra(AndroidVpnService.EXTRA_COMMAND_ID, ticket.id)
            }
            try {
                context.startService(intent)
            } catch (error: Throwable) {
                commands.discard(ticket)
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = false,
                )
            }
            try {
                commands.await(ticket, timeoutMillis).getOrThrow()
            } catch (error: Throwable) {
                throw VpnCommandException(
                    message = error.message ?: ConnectionStatusMessages.connectionStopFailed(initialState.appMode),
                    cause = error,
                    commandDispatched = true,
                )
            }
        }
    }

    private companion object {
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
) : IOException(message, cause) {
    /** Waiting ending is not evidence that the native operation failed. */
    val outcomeUnknown: Boolean = commandDispatched &&
        (cause is kotlinx.coroutines.CancellationException ||
            cause is com.kardinal.vpncontrol.AndroidRuntimeOutcomeUnknownException ||
            cause?.message == "RUNTIME_OUTCOME_UNKNOWN")
}
