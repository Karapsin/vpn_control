package com.kardinal.vpncontrol

import java.security.MessageDigest
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout

internal enum class AndroidRuntimeAction { START, STOP }

/** In-process command receipts. A service must claim the exact command before effects. */
internal class AndroidRuntimeCommands(
    private val clockMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val retentionMillis: Long = 300_000,
) {
    internal class Ticket internal constructor(
        val id: String, val action: AndroidRuntimeAction, internal val digest: ByteArray?, internal val expiresAt: Long,
    ) {
        internal val completion = CompletableDeferred<Result<Unit>>()
        internal var claimed = false
    }
    private val pending = mutableMapOf<String, Ticket>()

    @Synchronized fun register(action: AndroidRuntimeAction, config: String? = null): Ticket {
        prune()
        check(pending.size < 128) { "RUNTIME_COMMAND_CAPACITY" }
        return Ticket(UUID.randomUUID().toString(), action, config?.let(::digest), clockMillis() + retentionMillis)
            .also { pending[it.id] = it }
    }

    @Synchronized fun claim(id: String, action: AndroidRuntimeAction, config: String? = null): Boolean {
        prune()
        val ticket = pending[id] ?: return false
        if (ticket.claimed || ticket.action != action) return false
        if (ticket.digest != null && (config == null || !MessageDigest.isEqual(ticket.digest, digest(config)))) return false
        ticket.claimed = true
        return true
    }

    @Synchronized fun complete(id: String?, result: Result<Unit>) {
        prune()
        val ticket = pending.remove(id) ?: return
        ticket.completion.complete(result)
    }

    @Synchronized fun discard(ticket: Ticket) {
        // A disconnected waiter may invalidate an unstarted command, never a claimed
        // native action. The latter keeps its receipt until actual completion/expiry.
        if (!ticket.claimed && pending.remove(ticket.id) != null) {
            ticket.completion.complete(Result.failure(AndroidRuntimeOutcomeUnknownException()))
        }
    }

    fun prepareStart(id: String?, config: String, preparedId: String?, preparations: AndroidPreparedConnections,
        validate: (String) -> Unit = {})
        : com.kardinal.vpncontrol.control.ControlRuntimeConfiguration? {
        check(id == null || claim(id, AndroidRuntimeAction.START, config)) { "RUNTIME_COMMAND_STALE" }
        val prepared = preparations.consume(preparedId, config)
        check(preparedId == null || prepared != null) { "RUNTIME_PREPARATION_STALE" }
        validate(config)
        return prepared
    }

    suspend fun await(ticket: Ticket, timeoutMillis: Long): Result<Unit> =
        try {
            synchronized(this) { prune() }
            withTimeout(timeoutMillis) { ticket.completion.await() }
        }
        finally { discard(ticket) }

    private fun prune() {
        val expired = pending.values.filter { it.expiresAt <= clockMillis() }
        expired.forEach { ticket ->
            pending.remove(ticket.id)
            ticket.completion.complete(Result.failure(AndroidRuntimeOutcomeUnknownException()))
        }
    }

    private fun digest(value: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
}

internal class AndroidRuntimeOutcomeUnknownException : IllegalStateException("RUNTIME_OUTCOME_UNKNOWN")
