package com.kardinal.vpncontrol

import java.util.UUID

/** AtomicFile backup names identify the same private record, never another artifact. */
internal object AndroidInstallReceiptRecovery {
    enum class Decision { SESSION_PRESENT, INSTALLED, RETRY_PROOF, OUTCOME_UNKNOWN }
    data class Loaded(val receipts: List<AndroidInstallSessionReceipt>, val unavailable: Boolean)
    /** Package-manager identity plus the bytes of this app's installed base APK. */
    data class InstalledArtifact(val version: String, val build: Long, val sha256: String,
        val signers: Set<String>)
    fun load(names: List<String>, read: (String) -> AndroidInstallSessionReceipt): Loaded {
        val bases = names.mapNotNull { name ->
            val base = if (name.endsWith(".json.bak")) name.removeSuffix(".bak") else name
            if (!base.endsWith(".json")) return@mapNotNull null
            val id = base.removeSuffix(".json")
            try { if (UUID.fromString(id).toString() == id) base else null }
            catch (_: IllegalArgumentException) { null }
        }.distinct().sorted()
        var unavailable = false
        val receipts = bases.mapNotNull { base ->
            try { read(base).also { require("${it.id}.json" == base); validate(it) } }
            catch (_: Exception) { unavailable = true; null }
        }
        return Loaded(receipts, unavailable)
    }

    private fun validate(receipt: AndroidInstallSessionReceipt) {
        require(UUID.fromString(receipt.nonce).toString() == receipt.nonce)
        require(receipt.sessionId >= 0 || receipt.sessionId == -1 && receipt.phase == AndroidInstallSessionPhase.PREPARING)
        val version = receipt.version.split('.').map { part ->
            require(part.isNotEmpty() && part.all(Char::isDigit))
            part.toInt()
        }
        require(version.size == 3 && version[0] in 1..19 && version[1] in 0..19 && version[2] in 0..19)
        require(receipt.build > 0 && receipt.byteCount > 0 && receipt.createdAt >= 0)
        val digest = Regex("[0-9a-f]{64}")
        require(digest.matches(receipt.sha256) && receipt.signers.isNotEmpty() && receipt.signers.all(digest::matches))
        if (receipt.phase in setOf(AndroidInstallSessionPhase.AWAITING_CONFIRMATION, AndroidInstallSessionPhase.HANDED_OFF))
            require(!receipt.confirmation.isNullOrBlank())
    }

    /**
     * A committed session can disappear when PackageInstaller replaces this process before its
     * private callback runs. The installed base APK is conclusive only when every identity
     * recorded before commit still matches; a version match alone is never enough.
     */
    fun provesInstalled(receipt: AndroidInstallSessionReceipt, installed: InstalledArtifact): Boolean =
        receipt.phase in setOf(AndroidInstallSessionPhase.COMMITTING,
            AndroidInstallSessionPhase.AWAITING_CONFIRMATION, AndroidInstallSessionPhase.HANDED_OFF) &&
            receipt.version == installed.version && receipt.build.toLong() == installed.build &&
            receipt.sha256 == installed.sha256 && receipt.signers.isNotEmpty() &&
            receipt.signers == installed.signers

    fun decision(receipt: AndroidInstallSessionReceipt, sessionPresent: Boolean,
        installed: InstalledArtifact?): Decision = when {
        receipt.phase == AndroidInstallSessionPhase.UNKNOWN -> Decision.OUTCOME_UNKNOWN
        sessionPresent -> Decision.SESSION_PRESENT
        installed != null && provesInstalled(receipt, installed) -> Decision.INSTALLED
        installed == null && receipt.phase in setOf(AndroidInstallSessionPhase.COMMITTING,
            AndroidInstallSessionPhase.AWAITING_CONFIRMATION, AndroidInstallSessionPhase.HANDED_OFF) -> Decision.RETRY_PROOF
        else -> Decision.OUTCOME_UNKNOWN
    }

    fun cleanup(receipt: AndroidInstallSessionReceipt, cancelStatus: () -> Unit, cancelConfirmation: () -> Unit): Boolean {
        if (!receipt.terminal) return false
        var complete = true
        try { cancelStatus() } catch (_: Exception) { complete = false }
        try { cancelConfirmation() } catch (_: Exception) { complete = false }
        return complete
    }
}
