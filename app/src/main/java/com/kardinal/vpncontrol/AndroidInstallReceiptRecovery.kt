package com.kardinal.vpncontrol

import java.util.UUID

/** AtomicFile backup names identify the same private record, never another artifact. */
internal object AndroidInstallReceiptRecovery {
    data class Loaded(val receipts: List<AndroidInstallSessionReceipt>, val unavailable: Boolean)
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

    fun cleanup(receipt: AndroidInstallSessionReceipt, cancelStatus: () -> Unit, cancelConfirmation: () -> Unit): Boolean {
        if (!receipt.terminal) return false
        var complete = true
        try { cancelStatus() } catch (_: Exception) { complete = false }
        try { cancelConfirmation() } catch (_: Exception) { complete = false }
        return complete
    }
}
