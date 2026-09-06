package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import java.util.UUID
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withTimeoutOrNull

/** Opaque in-process capabilities; no configuration or credentials are stored here. */
internal class AndroidControlInteractions(
    private val ownerId: String,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val retentionMillis: Long = 120_000,
) {
    private data class Entry(val operationId: String, val action: ControlOperationId, val expires: Long,
        val completion: CompletableDeferred<ControlCode> = CompletableDeferred(), var session: String? = null,
        var consentLaunched: Boolean = false)
    private val entries = mutableMapOf<String, Entry>()
    private val mutableGeneration = MutableStateFlow(0L)
    val generation = mutableGeneration.asStateFlow()

    @Synchronized fun create(operationId: String, action: ControlOperationId): String {
        prune()
        require(action in setOf(ControlOperationId.ON, ControlOperationId.RESTART, ControlOperationId.UPDATES_INSTALL))
        check(entries.size < 32) { "BUSY" }
        return UUID.randomUUID().toString().also {
            entries[it] = Entry(operationId, action, clock() + retentionMillis)
            changed()
        }
    }

    @Synchronized fun tokenFor(operationId: String): String? {
        prune()
        return entries.entries.firstOrNull { it.value.operationId == operationId && !it.value.completion.isCompleted }?.key
    }

    @Synchronized fun attach(token: String, epoch: String, restoredSession: String?): String? {
        prune()
        if (epoch != ownerId) return null
        val entry = entries[token]?.takeUnless { it.completion.isCompleted } ?: return null
        if (entry.session != null) return entry.session.takeIf { restoredSession == it }
        if (restoredSession != null) return null
        return UUID.randomUUID().toString().also { entry.session = it }
    }

    @Synchronized fun claimConsent(token: String, session: String): Boolean {
        prune()
        val entry = entries[token] ?: return false
        if (entry.session != session || entry.consentLaunched || entry.completion.isCompleted) return false
        entry.consentLaunched = true
        return true
    }

    @Synchronized fun action(token: String, session: String): ControlOperationId? {
        prune()
        return entries[token]?.takeIf { it.session == session && !it.completion.isCompleted }?.action
    }

    /** Cancellation and the actual synchronous OS handoff share this one-shot boundary. */
    @Synchronized fun dispatchInstall(token: String, session: String, dispatch: () -> Unit): Boolean {
        if (action(token, session) != ControlOperationId.UPDATES_INSTALL) return false
        val entry = requireNotNull(entries[token])
        val succeeded = runCatching(dispatch).isSuccess
        entry.completion.complete(if (succeeded) ControlCode.OK else ControlCode.RUNTIME_FAILED)
        changed()
        return succeeded
    }

    @Synchronized fun resolve(token: String, session: String, result: ControlCode) {
        prune()
        val entry = entries[token] ?: return
        if (entry.session == session && result in setOf(ControlCode.OK, ControlCode.PERMISSION_DENIED) &&
            (entry.action != ControlOperationId.UPDATES_INSTALL || result != ControlCode.OK)) {
            entry.completion.complete(result)
            changed()
        }
    }

    suspend fun await(token: String): ControlCode {
        val deferred = synchronized(this) { prune(); entries[token]?.completion } ?: return ControlCode.INTERACTION_REQUIRED
        return withTimeoutOrNull(retentionMillis) { deferred.await() } ?: ControlCode.INTERACTION_REQUIRED
    }

    @Synchronized fun isActive(token: String): Boolean { prune(); return entries.containsKey(token) }
    /** Owner cancellation wakes a pending wait; it cannot replace a resolved OS answer. */
    @Synchronized fun cancel(operationId: String) {
        entries.values.filter { it.operationId == operationId }.forEach { it.completion.complete(ControlCode.CANCELLED) }
        changed()
    }
    @Synchronized fun finish(token: String) { entries.remove(token); changed() }
    private fun changed() { mutableGeneration.value++ }
    private fun prune() {
        val expired = entries.filterValues { it.expires <= clock() }.keys.toList()
        expired.forEach { entries.remove(it)?.completion?.complete(ControlCode.INTERACTION_REQUIRED) }
        if (expired.isNotEmpty()) changed()
    }
}
