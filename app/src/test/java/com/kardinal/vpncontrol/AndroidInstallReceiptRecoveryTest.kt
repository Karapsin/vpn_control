package com.kardinal.vpncontrol

import org.junit.Assert.*
import org.junit.Test

class AndroidInstallReceiptRecoveryTest {
    private val id = "b2d876f3-194c-4e8c-893e-e482a66c6f50"
    private fun receipt() = AndroidInstallSessionReceipt(id, "6e4905fb-d713-4dd5-a7fb-136cc12c56b5", 8, "2.3.4", 50,
        "a".repeat(64), 100, AndroidInstallSessionPhase.COMMITTING, signers = setOf("b".repeat(64)), createdAt = 0)

    @Test fun backupOnlyIsRecoveredOnceAndUnownedNamesAreNeverOpened() {
        val opened = mutableListOf<String>()
        val result = AndroidInstallReceiptRecovery.load(listOf("$id.json.bak", "$id.json", "foreign.json", "$id.json.new")) {
            opened += it; receipt()
        }
        assertEquals(listOf("$id.json"), opened)
        assertEquals(listOf(receipt()), result.receipts)
        assertFalse(result.unavailable)
    }

    @Test fun corruptOrMismatchedReceiptFailsClosedWithoutDiscardingOtherEvidence() {
        val broken = AndroidInstallReceiptRecovery.load(listOf("$id.json.bak")) { throw java.io.IOException("broken") }
        assertTrue(broken.unavailable)
        assertTrue(broken.receipts.isEmpty())
        val mismatched = AndroidInstallReceiptRecovery.load(listOf("$id.json")) { receipt().copy(id = "other") }
        assertTrue(mismatched.unavailable)
    }

    @Test fun malformedCorrelationOrArtifactMetadataFailsClosedBeforeAnySessionIsRecovered() {
        val valid = receipt()
        for (malformed in listOf(valid.copy(nonce = "other"), valid.copy(sessionId = -1),
            valid.copy(version = "garbled"), valid.copy(version = "2.20.1"), valid.copy(build = 0),
            valid.copy(sha256 = "corrupt"), valid.copy(byteCount = 0), valid.copy(signers = emptySet()),
            valid.copy(signers = setOf("wrong-signer")), valid.copy(createdAt = -1),
            valid.copy(phase = AndroidInstallSessionPhase.HANDED_OFF),
            valid.copy(phase = AndroidInstallSessionPhase.AWAITING_CONFIRMATION, confirmation = ""))) {
            val result = AndroidInstallReceiptRecovery.load(listOf("$id.json")) { malformed }
            assertTrue(result.unavailable)
            assertTrue(result.receipts.isEmpty())
        }
        val initial = AndroidInstallReceiptRecovery.load(listOf("$id.json")) {
            valid.copy(sessionId = -1, phase = AndroidInstallSessionPhase.PREPARING)
        }
        assertFalse(initial.unavailable)
        assertEquals(1, initial.receipts.size)
    }

    @Test fun onlyTerminalReceiptsReleaseBothCapabilitiesAndCleanupFailureRemainsRetryable() {
        var status = 0; var confirmation = 0
        assertFalse(AndroidInstallReceiptRecovery.cleanup(receipt(), { status++ }, { confirmation++ }))
        assertEquals(0, status)
        val terminal = receipt().copy(phase = AndroidInstallSessionPhase.INSTALLED)
        assertFalse(AndroidInstallReceiptRecovery.cleanup(terminal, { status++; error("temporary") }, { confirmation++ }))
        assertEquals(1, status); assertEquals(1, confirmation)
        assertTrue(AndroidInstallReceiptRecovery.cleanup(terminal, { status++ }, { confirmation++ }))
        assertEquals(2, status); assertEquals(2, confirmation)
    }
}
