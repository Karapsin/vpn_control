package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.data.AndroidSubscriptionControl
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidSubscriptionOwnerTest {
    @Test fun protectedSubscriptionMutationsRetainExactIdAndRevisionOnRetryAndNeverRetargetStaleIds() = runTest {
        var committed = ControlCommitted("owner", 0, PersistedState())
        var writes = 0
        var schedules = 0
        var failCommit = false
        val jobs = AndroidCommandJobs(backgroundScope)
        val control = AndroidSettingsControl("owner", backgroundScope, { committed },
            { _, _, _ -> error("settings path") }, { schedules++ }, { false }, mutationJobs = jobs,
            subscription = { operation, values, epoch, revision ->
                check(epoch == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                val plan = AndroidSubscriptionControl.plan(committed.value, operation, values,
                    { Result.success(Unit) }, { "stable-id" })
                if (failCommit) error("private failure")
                val next = committed.value.copy(subscriptions = plan.subscriptions, activeSubscriptionId = plan.activeId, profileSourceMode = plan.mode)
                writes++
                committed = committed.copy(revision = committed.revision + if (next == committed.value) 0 else 1, value = next)
                AndroidSettingsCommit(committed, true, mapOf("id" to ControlValue.Text(plan.targetId)))
            })
        val reader = AndroidControlReader("owner", { committed.value }, committedSnapshot = { committed },
            pendingRestart = { false }, settingsWrite = control::execute)
        fun request(id: String, operation: ControlOperationId, vararg args: Pair<String, String>) = ControlRequest(id,
            ControlCommand(operation, args.associate { it.first to ControlValue.Text(it.second) }), controllerId = "owner", ifRevision = committed.revision)
        val add = request("add", ControlOperationId.SUBSCRIPTIONS_ADD, "source" to "https://private.invalid/token")
        val accepted = reader.read(add.copy(asynchronous = true))
        assertEquals(ControlCode.ACCEPTED, accepted.code)
        assertFalse(accepted.final)
        val saved = reader.read(add)
        assertEquals(ControlCode.OK, saved.code); assertEquals(1L, saved.configurationRevision)
        assertEquals(mapOf("id" to ControlValue.Text("stable-id")), saved.data)
        assertFalse(saved.toString().contains("private.invalid"))
        val lease = requireNotNull(jobs.tryAcquireMutation())
        assertEquals(saved, reader.read(add))
        assertEquals(ControlCode.BUSY, reader.read(request("busy", ControlOperationId.SUBSCRIPTIONS_DELETE, "id" to "stable-id")).code)
        jobs.releaseMutation(lease)
        assertEquals(ControlCode.CONFLICT, reader.read(add.copy(requestId = "stale")).code)
        assertEquals(ControlCode.NOT_FOUND, reader.read(request("missing", ControlOperationId.SUBSCRIPTIONS_DELETE, "id" to "gone")).code)
        failCommit = true
        val failed = reader.read(request("failed", ControlOperationId.SUBSCRIPTIONS_UPDATE, "id" to "stable-id", "name" to "new"))
        assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code); assertEquals(1L, failed.configurationRevision)
        assertTrue(failed.data.isEmpty()); assertFalse(failed.toString().contains("private failure"))
        failCommit = false
        val noOp = reader.read(request("no-op", ControlOperationId.SUBSCRIPTIONS_UPDATE, "id" to "stable-id", "name" to ""))
        assertEquals(1L, noOp.configurationRevision)
        val delete = request("delete", ControlOperationId.SUBSCRIPTIONS_DELETE, "id" to "stable-id")
        val deleted = reader.read(delete)
        assertEquals(ControlCode.OK, deleted.code); assertEquals(2L, deleted.configurationRevision)
        assertEquals(mapOf("id" to ControlValue.Text("stable-id")), deleted.data)
        assertEquals(deleted, reader.read(delete)); assertTrue(committed.value.subscriptions.isEmpty())
        assertEquals(3, writes); assertEquals(3, schedules)
    }
}
