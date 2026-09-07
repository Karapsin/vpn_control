package com.kardinal.vpncontrol

internal typealias AndroidInstallSessionPhase = AppInstallSessionPhase

internal data class AndroidInstallSessionReceipt(
    val id: String,
    val nonce: String,
    val sessionId: Int,
    val version: String,
    val build: Int,
    val sha256: String,
    val byteCount: Long,
    val phase: AndroidInstallSessionPhase,
    val confirmation: String? = null,
    val signers: Set<String> = emptySet(),
    val createdAt: Long = System.currentTimeMillis(),
) {
    val terminal get() = phase in setOf(AndroidInstallSessionPhase.INSTALLED,
        AndroidInstallSessionPhase.FAILED, AndroidInstallSessionPhase.CANCELLED)
}

/** Persist before publishing transitions. Only an exact OS callback proves completion. */
internal class AndroidInstallSessionLifecycle(
    initial: AndroidInstallSessionReceipt,
    private val persist: (AndroidInstallSessionReceipt) -> Unit,
    private val published: (AndroidInstallSessionReceipt) -> Unit,
) {
    constructor(initial: AndroidInstallSessionReceipt, persist: (AndroidInstallSessionReceipt) -> Unit) :
        this(initial, persist, {})
    private var receipt = initial
    @Synchronized fun snapshot() = receipt
    @Synchronized fun canAbandon() = receipt.phase in setOf(AndroidInstallSessionPhase.PREPARING, AndroidInstallSessionPhase.STAGED)
    @Synchronized fun sessionCreated(sessionId: Int) {
        check(receipt.phase == AndroidInstallSessionPhase.PREPARING && receipt.sessionId == -1)
        require(sessionId >= 0)
        update(receipt.copy(sessionId = sessionId))
    }
    @Synchronized fun staged() {
        check(receipt.phase == AndroidInstallSessionPhase.PREPARING && receipt.sessionId >= 0)
        update(receipt.copy(phase = AndroidInstallSessionPhase.STAGED))
    }
    @Synchronized fun beforeCommit() {
        check(receipt.phase == AndroidInstallSessionPhase.STAGED)
        update(receipt.copy(phase = AndroidInstallSessionPhase.COMMITTING))
    }
    @Synchronized fun handedOff() {
        if (receipt.terminal || receipt.phase == AndroidInstallSessionPhase.HANDED_OFF) return
        check(receipt.phase == AndroidInstallSessionPhase.AWAITING_CONFIRMATION)
        update(receipt.copy(phase = AndroidInstallSessionPhase.HANDED_OFF))
    }
    @Synchronized fun callback(sessionId: Int, nonce: String, phase: AndroidInstallSessionPhase,
        confirmation: String? = null): Boolean {
        if (receipt.sessionId != sessionId || receipt.nonce != nonce || receipt.terminal ||
            canAbandon()) return false
        require(phase in setOf(AndroidInstallSessionPhase.AWAITING_CONFIRMATION,
            AndroidInstallSessionPhase.INSTALLED, AndroidInstallSessionPhase.FAILED, AndroidInstallSessionPhase.CANCELLED))
        // Repeated pending callbacks cannot demote an already launched confirmation.
        if (phase == AndroidInstallSessionPhase.AWAITING_CONFIRMATION &&
            receipt.phase == AndroidInstallSessionPhase.HANDED_OFF) return true
        update(receipt.copy(phase = phase, confirmation = confirmation ?: receipt.confirmation))
        return true
    }
    @Synchronized fun reconcile(sessionPresent: Boolean) {
        if (!sessionPresent && !receipt.terminal) update(receipt.copy(phase = AndroidInstallSessionPhase.UNKNOWN))
    }
    private fun update(next: AndroidInstallSessionReceipt) {
        persist(next)
        receipt = next
        published(next)
    }
}
