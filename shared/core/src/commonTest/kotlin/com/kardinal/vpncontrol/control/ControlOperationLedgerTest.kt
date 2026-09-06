package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationPhase
import com.kardinal.vpncontrol.model.ControlResult
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull

class ControlOperationLedgerTest {
    @Test
    fun duplicateRequestReturnsOriginalOperationBeforeBusyCheck() {
        val ledger = ControlOperationLedger("owner")
        val first = assertIs<ControlOperationAdmission.Started>(admit(ledger, "one"))
        val repeat = ledger.admit("different-generated-id", "request-one", ControlOperationId.ON, "hash-one", true, true, 0)
        assertEquals(first.operation, assertIs<ControlOperationAdmission.Existing>(repeat).operation)
        assertEquals(ControlCode.CONFLICT, assertIs<ControlOperationAdmission.Rejected>(
            ledger.admit("new", "request-one", ControlOperationId.ON, "different-hash", true, true, 0)).code)
    }

    @Test
    fun conflictingMutationsAreBusyButReadJobsAndCancellationRemainAvailable() {
        val ledger = ControlOperationLedger("owner")
        admit(ledger, "one")
        assertEquals(ControlCode.BUSY, assertIs<ControlOperationAdmission.Rejected>(admit(ledger, "two")).code)
        assertIs<ControlOperationAdmission.Started>(admit(ledger, "read", mutates = false))
        assertEquals(ControlCode.OK, ledger.requestCancellation("one", 0))
        assertEquals(ControlOperationPhase.CANCELLING, ledger.get("one", 0)?.phase)
        assertEquals(ControlCode.BUSY, assertIs<ControlOperationAdmission.Rejected>(admit(ledger, "two")).code)
        ledger.complete("one", result("one", ControlCode.CANCELLED), 1)
        assertIs<ControlOperationAdmission.Started>(admit(ledger, "two", now = 1))
    }

    @Test
    fun terminalResultsRequireMatchingIdentityAndCannotBeTimeoutFromAClient() {
        val ledger = ControlOperationLedger("owner")
        admit(ledger, "one")
        for (result in listOf(
            result("one", ControlCode.OK).copy(controllerId = "other"),
            result("one", ControlCode.OK).copy(requestId = "other"),
            result("one", ControlCode.OK).copy(operationId = "other"),
            result("one", ControlCode.TIMEOUT), result("one", ControlCode.OUTCOME_UNKNOWN),
        )) assertFailsWith<IllegalArgumentException> { ledger.complete("one", result, 0) }
        assertEquals(ControlOperationPhase.QUEUED, ledger.get("one", 0)?.phase)
    }

    @Test
    fun completionRetentionUsesCompletionTimeAndNeverEvictsAnActiveOperation() {
        val ledger = ControlOperationLedger("owner", completedCapacity = 2, retentionMillis = 100)
        admit(ledger, "active", mutates = false)
        for (index in 1..3) {
            admit(ledger, "done-$index", now = index.toLong())
            ledger.complete("done-$index", result("done-$index", ControlCode.OK), index.toLong())
        }
        assertEquals(setOf("active", "done-2", "done-3"), ledger.list(3).map { it.id }.toSet())
        assertNull(ledger.forRequest("request-done-1", 3))
        assertEquals(setOf("active", "done-3"), ledger.list(102).map { it.id }.toSet())
        assertEquals(listOf("active"), ledger.list(103).map { it.id })
        ledger.complete("active", result("active", ControlCode.OK), 500)
        assertEquals(listOf("active"), ledger.list(599).map { it.id })
        assertEquals(emptyList(), ledger.list(600))
    }

    @Test
    fun installerHandoffCanBecomeNonCancellableWithoutPretendingToBeFinished() {
        val ledger = ControlOperationLedger("owner")
        admit(ledger, "one")
        ledger.advance("one", ControlOperationPhase.AWAITING_USER, 0)
        ledger.advance("one", ControlOperationPhase.RUNNING, 1, cancellable = false)
        assertEquals(ControlCode.CONFLICT, ledger.requestCancellation("one", 1))
        assertNull(ledger.get("one", 1)?.result)
    }

    @Test
    fun progressAndTransitionsAreValidated() {
        val ledger = ControlOperationLedger("owner")
        admit(ledger, "one")
        assertFailsWith<IllegalArgumentException> {
            ledger.advance("one", ControlOperationPhase.RUNNING, 0, completedUnits = 3, totalUnits = 2)
        }
        ledger.advance("one", ControlOperationPhase.RUNNING, 0, completedUnits = 1, totalUnits = 2)
        ledger.complete("one", result("one", ControlCode.OK), 1)
        assertFailsWith<IllegalArgumentException> { ledger.advance("one", ControlOperationPhase.RUNNING, 1) }
        assertFailsWith<IllegalArgumentException> { ledger.complete("one", result("one", ControlCode.OK), 1) }
        assertFailsWith<IllegalArgumentException> { ledger.list(0) }
    }

    private fun admit(ledger: ControlOperationLedger, id: String, mutates: Boolean = true, now: Long = 0) =
        ledger.admit(id, "request-$id", ControlOperationId.ON, "hash-$id", mutates, true, now)
    private fun result(id: String, code: ControlCode) = ControlResult(
        "owner", "request-$id", code, configurationRevision = 0, operationId = id,
    )
}
