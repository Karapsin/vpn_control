package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperation
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationPhase
import com.kardinal.vpncontrol.model.ControlResult

sealed interface ControlOperationAdmission {
    data class Started(val operation: ControlOperation) : ControlOperationAdmission
    data class Existing(val operation: ControlOperation) : ControlOperationAdmission
    data class Rejected(val code: ControlCode) : ControlOperationAdmission
}

/**
 * Pure, bounded per-controller ledger. Access on the session's serialized state lane.
 * The adapter supplies monotonic milliseconds and collision-resistant opaque operation IDs.
 * Store a cryptographic request fingerprint, never command arguments or private input.
 */
class ControlOperationLedger(
    val controllerId: String,
    private val completedCapacity: Int = 256,
    private val retentionMillis: Long = 30 * 60 * 1000,
) {
    private data class Entry(
        var operation: ControlOperation,
        val fingerprint: String,
        val mutates: Boolean,
        var completedAt: Long? = null,
    )

    private val entries = linkedMapOf<String, Entry>()
    private val requests = mutableMapOf<String, String>()
    private var lastNow = 0L

    init {
        require(controllerId.isNotBlank())
        require(completedCapacity > 0 && retentionMillis > 0)
    }

    fun admit(
        id: String,
        requestId: String,
        operation: ControlOperationId,
        fingerprint: String,
        mutates: Boolean,
        cancellable: Boolean,
        now: Long,
    ): ControlOperationAdmission {
        expire(now)
        require(id.isNotBlank() && requestId.isNotBlank() && fingerprint.isNotBlank())
        requests[requestId]?.let { priorId ->
            val prior = entries.getValue(priorId)
            return if (prior.fingerprint == fingerprint && prior.operation.operation == operation && prior.mutates == mutates) {
                ControlOperationAdmission.Existing(prior.operation)
            } else ControlOperationAdmission.Rejected(ControlCode.CONFLICT)
        }
        require(id !in entries) { "Operation identifier collision" }
        if (mutates && entries.values.any { it.mutates && !it.operation.phase.terminal }) {
            return ControlOperationAdmission.Rejected(ControlCode.BUSY)
        }
        val created = ControlOperation(id, requestId, operation, ControlOperationPhase.QUEUED, cancellable)
        entries[id] = Entry(created, fingerprint, mutates)
        requests[requestId] = id
        return ControlOperationAdmission.Started(created)
    }

    fun get(id: String, now: Long): ControlOperation? {
        expire(now)
        return entries[id]?.operation
    }

    fun forRequest(requestId: String, now: Long): ControlOperation? {
        expire(now)
        return requests[requestId]?.let { entries[it]?.operation }
    }

    fun list(now: Long): List<ControlOperation> {
        expire(now)
        return entries.values.map { it.operation }
    }

    fun advance(
        id: String,
        phase: ControlOperationPhase,
        now: Long,
        completedUnits: Long? = null,
        totalUnits: Long? = null,
        cancellable: Boolean? = null,
    ): ControlOperation {
        expire(now)
        val entry = entries.getValue(id)
        val prior = entry.operation
        require(!phase.terminal) { "Use complete for terminal results" }
        require(phase in allowedNext(prior.phase)) { "Invalid operation transition" }
        val next = prior.copy(
            phase = phase,
            completedUnits = completedUnits ?: prior.completedUnits,
            totalUnits = totalUnits ?: prior.totalUnits,
            cancellable = cancellable ?: prior.cancellable,
        )
        entry.operation = next
        return next
    }

    /** Requesting cancellation is not a claim that external effects have stopped. */
    fun requestCancellation(id: String, now: Long): ControlCode {
        expire(now)
        val entry = entries[id] ?: return ControlCode.NOT_FOUND
        val prior = entry.operation
        if (prior.phase == ControlOperationPhase.CANCELLED) return ControlCode.OK
        if (prior.phase.terminal || !prior.cancellable) return ControlCode.CONFLICT
        if (prior.phase != ControlOperationPhase.CANCELLING) {
            entry.operation = prior.copy(phase = ControlOperationPhase.CANCELLING)
        }
        return ControlCode.OK
    }

    fun complete(id: String, result: ControlResult, now: Long): ControlOperation {
        expire(now)
        val entry = entries.getValue(id)
        val prior = entry.operation
        require(!prior.phase.terminal) { "Operation already completed" }
        require(result.final && result.code != ControlCode.ACCEPTED)
        require(result.requestId == prior.requestId && result.controllerId == controllerId && result.operationId == id)
        // A waiter timing out or losing the transport cannot complete the owner's job.
        require(result.code !in setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE, ControlCode.INCOMPATIBLE_PROTOCOL))
        val phase = when (result.code) {
            ControlCode.OK -> ControlOperationPhase.SUCCEEDED
            ControlCode.CANCELLED -> ControlOperationPhase.CANCELLED
            else -> ControlOperationPhase.FAILED
        }
        val next = prior.copy(phase = phase, result = result, cancellable = false)
        entry.operation = next
        entry.completedAt = now
        expire(now)
        return next
    }

    private fun expire(now: Long) {
        require(now >= lastNow) { "Operation clock must be monotonic" }
        lastNow = now
        val expired = entries.filterValues { entry ->
            entry.completedAt?.let { now - it >= retentionMillis } == true
        }.keys.toList()
        expired.forEach(::remove)
        val completed = entries.filterValues { it.operation.phase.terminal }.entries
            .sortedBy { it.value.completedAt }
        completed.take((completed.size - completedCapacity).coerceAtLeast(0)).forEach { remove(it.key) }
    }

    private fun remove(id: String) {
        entries.remove(id)?.let { requests.remove(it.operation.requestId) }
    }

    private fun allowedNext(phase: ControlOperationPhase): Set<ControlOperationPhase> = when (phase) {
        ControlOperationPhase.QUEUED -> setOf(ControlOperationPhase.RUNNING, ControlOperationPhase.AWAITING_USER)
        ControlOperationPhase.RUNNING -> setOf(ControlOperationPhase.RUNNING, ControlOperationPhase.AWAITING_USER)
        ControlOperationPhase.AWAITING_USER -> setOf(ControlOperationPhase.AWAITING_USER, ControlOperationPhase.RUNNING)
        ControlOperationPhase.CANCELLING -> setOf(ControlOperationPhase.CANCELLING)
        ControlOperationPhase.SUCCEEDED, ControlOperationPhase.FAILED, ControlOperationPhase.CANCELLED -> emptySet()
    }
}
