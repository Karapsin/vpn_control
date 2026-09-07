package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.AccessDeniedException

internal enum class DesktopWindowsNativeResourceDisposition {
    NO_MUTABLE_HANDOFF, PUBLISHED, PENDING_PUBLICATION, COMMITTED_CLEANUP_PENDING,
}

/** Decoded only from the authenticated broker or an admitted protected resource receipt. */
internal class DesktopWindowsNativeResourceResult(
    val resourceId: String,
    val kind: DesktopWindowsRuntimeResourceKind,
    val disposition: DesktopWindowsNativeResourceDisposition,
    val code: ControlCode? = null,
) {
    override fun toString() = "DesktopWindowsNativeResourceResult(<redacted>)"
}

internal class DesktopWindowsNativeResourceReconciliation(
    val jobId: String,
    entries: List<DesktopWindowsNativeResourceResult>,
    val protectedCleanupConfirmed: Boolean,
) {
    val resources = entries.toList()
    override fun toString() = "DesktopWindowsNativeResourceReconciliation(<redacted>)"
}

/** Native exit is established before entry. Resource uncertainty never implies a live runtime. */
internal class DesktopWindowsRuntimeResourceReconciliation private constructor(
    val job: DesktopWindowsRuntimeResourceJob,
    private val registry: DesktopWindowsRuntimeResourceJournalRegistry,
) {
    private var reconciled = false
    private val established = mutableMapOf<String, DesktopWindowsNativeResourceDisposition>()

    /** This adapter only reads native evidence. It never retries a cache write or invokes a runtime. */
    @Synchronized fun afterConfirmedExit(
        observe: () -> DesktopWindowsNativeResourceReconciliation,
    ): List<DesktopRuntimeResourceWarning> {
        if (reconciled) return emptyList()
        val native = try { observe().also(::validate) }
        catch (_: Exception) {
            return listOf(warning(ControlCode.OUTCOME_UNKNOWN,
                pending = job.resources.any { it.resourceId !in established }))
        }
        native.resources.forEach { result ->
            when (result.disposition) {
                DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF -> established[result.resourceId] = result.disposition
                DesktopWindowsNativeResourceDisposition.PUBLISHED,
                DesktopWindowsNativeResourceDisposition.COMMITTED_CLEANUP_PENDING ->
                    established[result.resourceId] = DesktopWindowsNativeResourceDisposition.PUBLISHED
                DesktopWindowsNativeResourceDisposition.PENDING_PUBLICATION -> Unit
            }
        }
        val noHandoff = native.resources.all { it.disposition == DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF }
        val allPublished = native.resources.all { it.disposition == DesktopWindowsNativeResourceDisposition.PUBLISHED }
        if ((noHandoff || allPublished) && native.protectedCleanupConfirmed) {
            try {
                registry.reconcile(job, if (noHandoff) DesktopWindowsRuntimeResourceJobDisposition.NO_MUTABLE_HANDOFF
                    else DesktopWindowsRuntimeResourceJobDisposition.PUBLICATION_AND_CLEANUP_CONFIRMED)
                reconciled = true
                return emptyList()
            } catch (failure: Exception) {
                // Native publication remains known even when deleting ordinary correlation fails.
                return listOf(warning(publicationCode(failure), pending = false))
            }
        }
        return native.resources.map { result ->
            warning(result.code ?: ControlCode.PERSISTENCE_FAILED,
                pending = result.disposition == DesktopWindowsNativeResourceDisposition.PENDING_PUBLICATION &&
                    result.resourceId !in established)
        }.distinct()
    }

    private fun validate(native: DesktopWindowsNativeResourceReconciliation) {
        check(native.jobId == job.jobId && native.resources.size == job.resources.size)
        check(native.resources.map { it.resourceId }.distinct().size == native.resources.size)
        val expected = job.resources.associate { it.resourceId to it.kind }
        check(native.resources.all { expected[it.resourceId] == it.kind })
        check(native.resources.all { result ->
            when (established[result.resourceId]) {
                DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF ->
                    result.disposition == DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF
                DesktopWindowsNativeResourceDisposition.PUBLISHED ->
                    result.disposition != DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF
                else -> true
            }
        })
        check(native.resources.all { result ->
            if (result.disposition in setOf(DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF,
                    DesktopWindowsNativeResourceDisposition.PUBLISHED)) result.code == null
            else result.code in PUBLICATION_CODES
        })
        // A candidate cannot both execute mutable work and claim that nothing was handed off.
        check(native.resources.none { it.disposition == DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF } ||
            native.resources.all { it.disposition == DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF })
        check(!native.protectedCleanupConfirmed || native.resources.all {
            it.disposition in setOf(DesktopWindowsNativeResourceDisposition.NO_MUTABLE_HANDOFF,
                DesktopWindowsNativeResourceDisposition.PUBLISHED)
        })
    }

    private fun warning(code: ControlCode, pending: Boolean) = DesktopRuntimeResourceWarning(code, job.jobId,
        if (pending) DesktopRuntimeResourceDisposition.PENDING_PUBLICATION else DesktopRuntimeResourceDisposition.COMMITTED_CLEANUP_PENDING)

    companion object {
        private val PUBLICATION_CODES = setOf(ControlCode.PERSISTENCE_FAILED, ControlCode.PERMISSION_DENIED,
            ControlCode.CONFLICT, ControlCode.OUTCOME_UNKNOWN)

        /** Durable correlation precedes UAC and every native input. Failed admission preserves actual A. */
        fun retain(job: DesktopWindowsRuntimeResourceJob,
            registry: DesktopWindowsRuntimeResourceJournalRegistry?): DesktopWindowsRuntimeResourceReconciliation {
            val admitted = registry ?: throw DesktopWindowsRuntimeFailure("UNAVAILABLE",
                stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
            try { admitted.retain(job) }
            catch (failure: Exception) {
                val code = when {
                    failure is AccessDeniedException || failure is SecurityException ||
                        failure is WindowsInstallNativeFailure && failure.code == 5 -> "PERMISSION_DENIED"
                    failure.message in setOf("CONFLICT", "BUSY", "PERMISSION_DENIED") -> failure.message!!
                    else -> "PERSISTENCE_FAILED"
                }
                throw DesktopWindowsRuntimeFailure(code, stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
            } catch (_: OutOfMemoryError) {
                throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS)
            }
            return DesktopWindowsRuntimeResourceReconciliation(job, admitted)
        }

        private fun publicationCode(failure: Exception): ControlCode = when {
            failure.message in PUBLICATION_CODES.map { it.name } -> ControlCode.valueOf(failure.message!!)
            failure is AccessDeniedException || failure is SecurityException ||
                failure is WindowsInstallNativeFailure && failure.code == 5 -> ControlCode.PERMISSION_DENIED
            else -> ControlCode.PERSISTENCE_FAILED
        }
    }
}
