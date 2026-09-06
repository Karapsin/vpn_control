package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidRoutingControl
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingOwnerTest {
    @Test fun routingWritesShareGuardsLeaseDedupAndReturnOwnNormalizedCommit() = runTest {
        var committed = ControlCommitted("owner", 0, PersistedState())
        var writes = 0
        val jobs = AndroidCommandJobs(backgroundScope)
        val apps = listOf(InstalledApp("app.browser", "Browser", false))
        val owner = AndroidSettingsControl("owner", backgroundScope, { committed },
            { _, _, _ -> error("Settings callback must not run") }, {}, { false }, mutationJobs = jobs,
            routing = { operation, arguments, epoch, revision ->
                check(epoch == committed.controllerId && (revision == null || revision == committed.revision)) { "CONFLICT" }
                val rules = AndroidRoutingControl.plan(committed.value, operation, arguments, apps)
                writes++
                committed = committed.copy(revision = committed.revision + if (rules != committed.value.routingRules) 1 else 0,
                    value = committed.value.copy(routingRules = rules))
                AndroidSettingsCommit(committed, false)
            })
        fun request(id: String, revision: Long) = ControlRequest(id, ControlCommand(ControlOperationId.ROUTING_SET,
            mapOf("key" to ControlValue.Text("direct-domains"), "value" to ControlValue.Text("[\"EXAMPLE.COM\",\"example.com\"]"))),
            controllerId = "owner", ifRevision = revision)
        val lease = requireNotNull(jobs.tryAcquireMutation())
        assertEquals(ControlCode.BUSY, owner.execute(request("busy", 0)).code)
        assertEquals(0, writes)
        jobs.releaseMutation(lease)
        val first = owner.execute(request("first", 0))
        assertEquals(ControlCode.OK, first.code)
        assertEquals(1, first.configurationRevision)
        assertEquals(mapOf("direct-domains" to ControlValue.ArrayValue(listOf(ControlValue.Text("example.com")))), first.data)
        val add = ControlRequest("add", ControlCommand(ControlOperationId.ROUTING_APPS_ADD,
            mapOf("package" to ControlValue.Text("app.browser"))), controllerId = "owner", ifRevision = 1)
        assertEquals(ControlCode.OK, owner.execute(add).code)
        assertEquals(2, committed.revision)
        assertEquals(first, owner.execute(request("first", 0)))
        assertEquals(2, writes)
        assertEquals(ControlCode.CONFLICT, owner.execute(request("stale", 0)).code)
        assertEquals(2, writes)
        assertEquals(ControlCode.CONFLICT, owner.execute(add.copy(controllerId = "old-owner")).code)
        assertEquals(2, writes)
    }

    @Test fun installedAppListBindsSelectionToCapturedConfigurationAndRejectsMalformedSearchBeforeLoading() = runTest {
        var loads = 0
        val reader = AndroidControlReader("owner", { error("Must use committed snapshot") },
            committedSnapshot = { ControlCommitted("owner", 11, PersistedState(routingRules = RoutingRules(proxyPackages = listOf("app.browser")))) },
            installedApps = { loads++; listOf(InstalledApp("app.browser", "Browser", false)) })
        val request = ControlRequest("list", ControlCommand(ControlOperationId.ROUTING_APPS_LIST,
            mapOf("search" to ControlValue.Text("BROWSER"))))
        val result = reader.read(request)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(11, result.configurationRevision)
        val row = ((result.data.getValue("apps") as ControlValue.ArrayValue).values.single() as ControlValue.ObjectValue).values
        assertEquals(ControlValue.BooleanValue(true), row["selected"])
        assertEquals(1, loads)
        assertEquals(ControlCode.INVALID_ARGUMENT, reader.read(request.copy(command = request.command.copy(
            arguments = mapOf("search" to ControlValue.Null)))).code)
        assertEquals(1, loads)
    }
}
