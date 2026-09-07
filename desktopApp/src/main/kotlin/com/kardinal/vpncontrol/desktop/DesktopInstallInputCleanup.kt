package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.util.concurrent.ConcurrentHashMap

/** Owner maintenance only. Inspection never launches a worker or removes installation evidence. */
internal class DesktopInstallInputCleanup(
    private val read: () -> Result<List<DesktopInstallCorrelationRecovery>>,
    private val release: (DesktopInstallCorrelation, DesktopInstallJobReceipt) -> Result<Unit>,
    private val releaseNotStarted: ((DesktopInstallCorrelationRecovery) -> Result<Unit>)? = null,
) {
    private data class Outcome(val receipt: DesktopInstallJobReceipt?, val notStartedCode: ControlCode?)
    private fun outcome(record: DesktopInstallCorrelationRecovery) = Outcome(record.receipt,
        record.code.takeIf { record.notStarted && record.receipt == null })
    private val completed = ConcurrentHashMap<DesktopInstallCorrelationRecord, Pair<Outcome, ControlCode>>()
    fun decorate(records: List<DesktopInstallCorrelationRecovery>): List<DesktopInstallCorrelationRecovery> = records.map { record ->
        record.copy(cleanupCode = record.binding?.let { completed[it] }?.takeIf { it.first == outcome(record) }?.second)
    }
    fun reconcile(ownerId: String): Result<Unit> = runCatching {
        val records = read().getOrThrow()
        completed.keys.retainAll(records.mapNotNull { it.binding }.toSet())
        if (records.any { it.blocksInstallation }) return@runCatching
        var failed = false
        for (record in records) {
            val binding = record.binding ?: continue
            val receipt = record.receipt
            if (binding.correlation.controllerId == ownerId) continue
            if (receipt != null) {
                if (!receipt.phase.terminal) continue
            } else if (!record.notStarted || releaseNotStarted == null || record.code !in setOf(
                    ControlCode.CANCELLED, ControlCode.PERMISSION_DENIED, ControlCode.INTERACTION_REQUIRED, ControlCode.RUNTIME_FAILED)) continue
            val identity = outcome(record)
            if (completed[binding] == (identity to ControlCode.OK)) continue
            val result = runCatching {
                if (receipt != null) {
                    check(receipt.jobId == binding.jobId)
                    release(binding.correlation, receipt).getOrThrow()
                } else requireNotNull(releaseNotStarted).invoke(record).getOrThrow()
            }
            completed[binding] = identity to if (result.isSuccess) ControlCode.OK else ControlCode.PERSISTENCE_FAILED
            failed = failed || result.isFailure
        }
        check(!failed) { ControlCode.PERSISTENCE_FAILED.name }
    }
}
