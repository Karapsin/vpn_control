package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.model.*
import java.io.File
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidUpdateInstallControlTest {
    private class Fixture(scope: CoroutineScope) {
        var state = AppUpdateState()
        var pins = 0
        var launches = 0
        var released: Boolean? = null
        var invalid = false
        val asset = UpdateAsset(UpdatePlatform.ANDROID, "arm64-v8a", UpdatePackageType.APK, "2.2.0", "update.apk",
            "https://github.com/synthetic/update.apk", "a".repeat(64), 10)
        val engine = AndroidUpdateControl({ scope.launch { it() } }, "1.0.0", 10,
            { UpdateManifest(1, 20, "v2.2.0", "https://github.com/synthetic", listOf(asset)) }, { asset },
            { File("synthetic-verified") }, { _, _, _ -> }, {}, {}, { state = it(state) })
        val interactions = AndroidControlInteractions("owner")
        val install = AndroidUpdateInstallControl(engine, interactions) {
            pins++
            object : AndroidUpdateInstallControl.Pinned {
                override val version = "2.2.0"
                override suspend fun verify() { check(!invalid) }
                override fun dispatch(launcher: (android.content.Intent) -> Unit) { launches++ }
                override fun release(handedOff: Boolean) { released = handedOff }
            }
        }
        val jobs = AndroidCommandJobs(scope)
        val owner = AndroidSettingsControl("owner", scope, { ControlCommitted("owner", 7, PersistedState()) },
            { _, _, _ -> error("No writes") }, {}, { null }, mutationJobs = jobs, updates = { engine }, updateInstall = { install })
        suspend fun prepare() { engine.check(); engine.downloadChecked() }
        fun request(id: String = "install", interactive: Boolean = true, revision: Long = 7) = ControlRequest(id,
            ControlCommand(ControlOperationId.UPDATES_INSTALL), controllerId = "owner", ifRevision = revision, interactive = interactive)
        suspend fun status(operation: String) = owner.execute(ControlRequest("status", ControlCommand(ControlOperationId.OPERATIONS_STATUS,
            mapOf("id" to ControlValue.Text(operation))), controllerId = "owner"))
    }

    @Test fun noninteractiveAndStaleRequestsHaveNoEffectsAndHandoffIsNotInstalled() = runTest {
        val f = Fixture(backgroundScope); f.prepare()
        assertEquals(ControlCode.INTERACTION_REQUIRED, f.owner.execute(f.request(interactive = false)).code)
        assertEquals(ControlCode.CONFLICT, f.owner.execute(f.request(revision = 6)).code)
        assertEquals(0, f.pins)
        val request = f.request()
        val accepted = f.owner.execute(request)
        runCurrent()
        val operation = requireNotNull(accepted.operationId)
        val token = requireNotNull(f.interactions.tokenFor(operation))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        assertEquals(ControlCode.BUSY, f.engine.execute(ControlOperationId.UPDATES_DISMISS).code)
        assertTrue(f.install.dispatch(token, session) { error("fake pin owns dispatch") })
        runCurrent()
        val result = f.status(operation)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(ControlValue.BooleanValue(true), result.data["installerStarted"])
        assertEquals(ControlValue.Null, result.data["installed"])
        assertTrue(result.warnings.contains("INSTALLER_STARTED_NOT_INSTALLED"))
        assertEquals(result.copy(requestId = request.requestId), f.owner.execute(request))
        assertEquals(1, f.launches); assertEquals(true, f.released)
        assertEquals(AppUpdatePhase.INSTALLING, f.state.phase)
        assertFalse(f.jobs.busy.value)
    }

    @Test fun cancelledConsentCleansPinAndNeverDispatches() = runTest {
        val f = Fixture(backgroundScope); f.prepare()
        val result = f.owner.execute(f.request()); runCurrent()
        val id = requireNotNull(result.operationId)
        val token = requireNotNull(f.interactions.tokenFor(id))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        val cancelled = f.owner.execute(ControlRequest("cancel", ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = "owner", ifRevision = 7))
        assertEquals(ControlCode.OK, cancelled.code)
        assertEquals(ControlCode.CANCELLED, f.status(id).code)
        assertFalse(f.install.dispatch(token, session) {})
        assertEquals(false, f.released); assertEquals(0, f.launches); assertFalse(f.engine.busy())
    }

    @Test fun changedArtifactFailsWithoutInstallingAndReleasesSlot() = runTest {
        val f = Fixture(backgroundScope); f.prepare()
        val result = f.owner.execute(f.request()); runCurrent()
        val id = requireNotNull(result.operationId)
        val token = requireNotNull(f.interactions.tokenFor(id))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        f.invalid = true
        assertFalse(f.install.dispatch(token, session) {})
        runCurrent()
        assertEquals(ControlCode.RUNTIME_FAILED, f.status(id).code)
        assertEquals(0, f.launches); assertEquals(false, f.released)
        assertEquals(AppUpdatePhase.READY, f.state.phase)
    }

    @Test fun acknowledgedDispatchSurvivesOwnerWaitCancellationWithoutDeletingInstallerInput() = runTest {
        val f = Fixture(backgroundScope); f.prepare()
        var result: AndroidUpdateOutcome? = null
        val worker = launch { result = f.install.execute("direct") { true } }
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor("direct"))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        assertTrue(f.install.dispatch(token, session) {})
        // Completion is queued but the original waiter has not resumed.
        worker.cancel(); worker.join()
        assertEquals(ControlCode.OK, result?.code)
        assertEquals(ControlValue.BooleanValue(true), result?.data?.get("installerStarted"))
        assertEquals(true, f.released)
        assertEquals(AppUpdatePhase.INSTALLING, f.state.phase)
        assertFalse(f.engine.busy())
    }
}
