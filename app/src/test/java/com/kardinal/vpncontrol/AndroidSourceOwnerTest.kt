package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.data.AndroidSourceControl
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidSourceOwnerTest {
    @Test fun protectedReaderSourceWritesUseOwnerLeaseGuardsAndReplayExactCommittedResult() = runTest {
        var state = ControlCommitted("owner", 0, PersistedState(subscriptions = listOf(
            SubscriptionSource(id = "one", url = "https://private.invalid/one"),
            SubscriptionSource(id = "two", url = "https://private.invalid/two")), activeSubscriptionId = "one"))
        val jobs = AndroidCommandJobs(backgroundScope)
        var commits = 0
        var schedules = 0
        var scheduleFails = false
        val owner = AndroidSettingsControl("owner", backgroundScope, { state },
            { _, _, _ -> error("Settings commit must not run") },
            { schedules++; if (scheduleFails) error("PRIVATE_SCHEDULER_ERROR") }, { false }, mutationJobs = jobs,
            setSource = { args, epoch, revision ->
                check(epoch == state.controllerId && (revision == null || revision == state.revision)) { "CONFLICT" }
                val (mode, id) = AndroidSourceControl.target(state.value, args)
                val next = state.value.copy(profileSourceMode = mode, activeSubscriptionId = id)
                commits++
                state = state.copy(revision = state.revision + if (next == state.value) 0 else 1, value = next)
                AndroidSettingsCommit(state, schedulingChanged = true)
            })
        val reader = AndroidControlReader("owner", { state.value }, committedSnapshot = { state },
            pendingRestart = { false }, settingsWrite = owner::execute)
        fun request(id: String, source: String, revision: Long = state.revision, subscription: String? = null) =
            ControlRequest(id, ControlCommand(ControlOperationId.SOURCE_SET,
                mapOf("source" to ControlValue.Text(source)) + (subscription?.let { mapOf("subscription-id" to ControlValue.Text(it)) } ?: emptyMap())),
                controllerId = "owner", ifRevision = revision)
        val first = request("first", "subscription", subscription = "two")
        val result = reader.read(first)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(1L, result.configurationRevision)
        assertEquals(ControlValue.Text("two"), result.data["subscriptionId"])
        assertFalse(result.toString().contains("private.invalid"))
        val lease = requireNotNull(jobs.tryAcquireMutation())
        assertEquals(result, reader.read(first)) // Lost response retry works even while another GUI action owns the lease.
        assertEquals(ControlCode.BUSY, reader.read(request("busy", "all")).code)
        jobs.releaseMutation(lease)
        assertEquals(1, commits); assertEquals(1, schedules)
        assertEquals(ControlCode.CONFLICT, reader.read(first.copy(command = ControlCommand(ControlOperationId.SOURCE_SET,
            mapOf("source" to ControlValue.Text("all"))))).code)
        assertEquals(ControlCode.CONFLICT, reader.read(request("old-revision", "all", 0)).code)
        assertEquals(ControlCode.CONFLICT, reader.read(request("old-owner", "all").copy(controllerId = "old")).code)
        assertEquals(ControlCode.NOT_FOUND, reader.read(request("removed", "subscription", subscription = "gone")).code)
        assertEquals("two", state.value.activeSubscriptionId)
        assertEquals(1, commits)
        val noOp = reader.read(request("no-op", "subscription", subscription = "two"))
        assertEquals(ControlCode.OK, noOp.code); assertEquals(1L, noOp.configurationRevision)
        scheduleFails = true
        val partial = request("scheduler-failure", "current-locations")
        val failed = reader.read(partial)
        assertEquals(ControlCode.RUNTIME_FAILED, failed.code)
        assertEquals(2L, failed.configurationRevision)
        assertEquals(ControlValue.BooleanValue(true), failed.data["configurationCommitted"])
        assertEquals(ProfileSourceMode.CURRENT_LOCATIONS, state.value.profileSourceMode)
        assertFalse(failed.toString().contains("PRIVATE_SCHEDULER_ERROR"))
        assertEquals(failed, reader.read(partial))
        assertEquals(3, commits); assertEquals(3, schedules)
    }

    @Test fun unsupportedSourceCallbackAndUnknownRuntimeRejectBeforeWrites() = runTest {
        val snapshot = ControlCommitted("owner", 0, PersistedState())
        var writes = 0
        val request = ControlRequest("source", ControlCommand(ControlOperationId.SOURCE_SET,
            mapOf("source" to ControlValue.Text("current-locations"))), controllerId = "owner", ifRevision = 0)
        val unsupported = AndroidSettingsControl("owner", backgroundScope, { snapshot },
            { _, _, _ -> error("must not write") }, {}, { false })
        assertEquals(ControlCode.UNSUPPORTED, unsupported.execute(request).code)
        val unknown = AndroidSettingsControl("owner", backgroundScope, { snapshot },
            { _, _, _ -> error("must not write") }, {}, { null },
            setSource = { _, _, _ -> writes++; AndroidSettingsCommit(snapshot, false) })
        assertEquals(ControlCode.UNAVAILABLE, unknown.execute(request).code)
        assertEquals(0, writes)
    }
}
