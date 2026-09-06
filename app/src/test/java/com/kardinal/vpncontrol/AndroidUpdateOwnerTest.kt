package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.io.File
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidUpdateOwnerTest {
    @Test fun unknownRuntimeDoesNotBlockUpdatesAndGuardsReplayCancellationAndProgressRemainAuthoritative() = runTest {
        var ui = AppUpdateState()
        val state = ControlCommitted("owner", 7L, PersistedState())
        val jobs = AndroidCommandJobs(backgroundScope)
        val started = CompletableDeferred<Unit>(); val cleanup = CompletableDeferred<Unit>(); val release = CompletableDeferred<Unit>()
        var checks = 0
        val asset = UpdateAsset(UpdatePlatform.ANDROID, "arm64-v8a", UpdatePackageType.APK, "2.2.0", "update.apk",
            "https://github.com/synthetic/update.apk", "a".repeat(64), 10)
        lateinit var updates: AndroidUpdateControl
        updates = AndroidUpdateControl(jobs::launch, "1.0.0", 10,
            { checks++; UpdateManifest(1, 20, "v2.2.0", "https://github.com/synthetic", listOf(asset)) }, { asset },
            { updates.progress(4, 10); started.complete(Unit); awaitCancellation() }, { _, _, _ -> },
            { cleanup.complete(Unit); release.await() }, {}, { ui = it(ui) })
        val owner = AndroidSettingsControl("owner", backgroundScope, { state }, { _, _, _ -> error("No configuration mutation") },
            {}, { null }, mutationJobs = jobs, updates = { updates }, updateInspection = { updates.inspection { ui } })
        fun request(id: String, operation: ControlOperationId, async: Boolean = false, revision: Long = 7,
            args: Map<String, ControlValue> = emptyMap()) = ControlRequest(id, ControlCommand(operation, args),
            controllerId = "owner", ifRevision = revision, asynchronous = async)
        assertEquals(ControlCode.CONFLICT, owner.execute(request("stale", ControlOperationId.UPDATES_CHECK, revision = 6)).code)
        assertEquals(0, checks)
        val checkedRequest = request("check", ControlOperationId.UPDATES_CHECK)
        val checked = owner.execute(checkedRequest)
        assertEquals(ControlCode.OK, checked.code); assertEquals(7L, checked.configurationRevision)
        assertTrue(checked.warnings.contains("PENDING_RESTART_STATE_UNAVAILABLE"))
        assertEquals(ControlValue.BooleanValue(true), checked.data["checked"])
        val download = owner.execute(request("download", ControlOperationId.UPDATES_DOWNLOAD, async = true))
        assertEquals(ControlCode.ACCEPTED, download.code)
        started.await()
        assertEquals(checked, owner.execute(checkedRequest))
        assertEquals(ControlCode.BUSY, owner.execute(request("busy", ControlOperationId.UPDATES_CHECK)).code)
        val listed = owner.execute(ControlRequest("list", ControlCommand(ControlOperationId.OPERATIONS_LIST), controllerId = "owner"))
        val rows = (listed.data.getValue("operations") as ControlValue.ArrayValue).values
        val row = rows.map { (it as ControlValue.ObjectValue).values }.single { it["id"] == ControlValue.Text(download.operationId!!) }
        assertEquals(ControlValue.IntegerValue(4), row["completedUnits"])
        assertEquals(ControlValue.BooleanValue(true), row["cancellable"])
        val cancelRequest = request("cancel", ControlOperationId.OPERATIONS_CANCEL,
            args = mapOf("id" to ControlValue.Text(download.operationId!!)))
        val cancelled = async { owner.execute(cancelRequest) }
        cleanup.await(); assertFalse(cancelled.isCompleted); assertTrue(jobs.busy.value)
        release.complete(Unit)
        assertEquals(ControlCode.OK, cancelled.await().code); assertFalse(jobs.busy.value)
        assertEquals(cancelled.await(), owner.execute(cancelRequest))
        val terminal = owner.execute(ControlRequest("status", ControlCommand(ControlOperationId.OPERATIONS_STATUS,
            mapOf("id" to ControlValue.Text(download.operationId!!))), controllerId = "owner"))
        assertEquals(ControlCode.CANCELLED, terminal.code)
        assertEquals(ControlCode.OK, owner.execute(request("dismiss", ControlOperationId.UPDATES_DISMISS)).code)
        assertNull(updates.checkedStatus())
    }
}
