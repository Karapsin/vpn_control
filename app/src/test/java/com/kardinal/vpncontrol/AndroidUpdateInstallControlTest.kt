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
    @Test fun foreignInteractionSessionCannotPrepareOrCommitPackageInstallation() = runTest {
        val f = Fixture(backgroundScope)
        var preparations = 0
        var leavesAwaiting = 0
        val install = AndroidUpdateInstallControl(f.engine, f.interactions, recover = {
            object : AndroidUpdateInstallControl.Pinned {
                override val version = "2.2.0"
                override suspend fun verify() {}
                override suspend fun prepareDispatch() { preparations++ }
                override fun dispatch(launcher: (android.content.Intent) -> Unit) { error("foreign session") }
                override fun release(handedOff: Boolean) {}
            }
        }, pin = { error("No new session") })
        val work = async { install.execute("protected") { if (!it) leavesAwaiting++; true } }
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor("protected"))
        requireNotNull(f.interactions.attach(token, "owner", null))
        assertFalse(install.dispatch(token, "foreign-session") {})
        assertEquals(0, preparations)
        assertEquals(0, leavesAwaiting)
        assertFalse(work.isCompleted)
        install.cancel("protected")
        assertEquals(ControlCode.CANCELLED, work.await().code)
    }

    @Test fun confirmationLaunchedBeforeJournalFailureStillReportsHandoff() = runTest {
        val f = Fixture(backgroundScope)
        var launched = false
        val install = AndroidUpdateInstallControl(f.engine, f.interactions, recover = {
            object : AndroidUpdateInstallControl.Pinned {
                override val version = "2.2.0"
                override suspend fun verify() {}
                override fun handedOff() = launched
                override fun dispatch(launcher: (android.content.Intent) -> Unit) {
                    launched = true
                    error("Receipt fsync failed after OS acknowledgement")
                }
                override fun release(handedOff: Boolean) { assertTrue(handedOff) }
            }
        }, pin = { error("No new session") })
        val work = async { install.execute("launched") { true } }
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor("launched"))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        install.dispatch(token, session) {}
        val result = work.await()
        assertEquals(ControlCode.OK, result.code)
        assertEquals(ControlValue.BooleanValue(true), result.data["installerStarted"])
    }
    @Test fun installReceiptDoesNotOverwriteNewerCheckedAvailabilityAndSurvivesDismiss() = runTest {
        val f = Fixture(backgroundScope)
        val session = AppInstallSessionStatus("receipt", AppInstallSessionPhase.INSTALLED, "1.1.0", false)
        f.engine.installSessionChanged(session)
        f.prepare()
        assertEquals(AppUpdatePhase.READY, f.state.phase)
        assertEquals("2.2.0", f.state.availableVersion)
        assertEquals(session, f.state.installSession)
        f.engine.execute(ControlOperationId.UPDATES_DISMISS)
        assertEquals(session, f.state.installSession)
        assertEquals(AppUpdatePhase.IDLE, f.state.phase)
    }
    @Test fun recoveredSessionUsesOwnerReservationAndNeverCreatesAnotherSession() = runTest {
        val f = Fixture(backgroundScope)
        var abandoned = false
        val recovered = object : AndroidUpdateInstallControl.Pinned {
            override val version = "2.2.0"
            override suspend fun verify() {}
            override fun dispatch(launcher: (android.content.Intent) -> Unit) {}
            override fun release(handedOff: Boolean) { abandoned = !handedOff }
        }
        val install = AndroidUpdateInstallControl(f.engine, f.interactions, recover = { recovered },
            pin = { error("Recovery must not create a new session") })
        val work = async { install.execute("recovered") { true } }
        runCurrent()
        assertTrue(f.engine.busy())
        assertEquals(ControlCode.BUSY, f.engine.execute(ControlOperationId.UPDATES_CHECK).code)
        assertEquals(ControlCode.BUSY, f.engine.execute(ControlOperationId.UPDATES_DISMISS).code)
        val token = requireNotNull(f.interactions.tokenFor("recovered"))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        assertTrue(install.dispatch(token, session) {})
        assertEquals(ControlCode.OK, work.await().code)
        assertFalse(abandoned)
        assertFalse(f.engine.busy())
        // A recovered receipt does not fabricate a checked/downloaded manifest in this owner.
        assertEquals(AppUpdatePhase.IDLE, f.state.phase)
    }

    @Test fun exactTerminalCallbackBeforeConfirmationDeterminesResultAndOuterState() = runTest {
        for ((phase, code, outer) in listOf(
            Triple(AppInstallSessionPhase.INSTALLED, ControlCode.OK, AppUpdatePhase.IDLE),
            Triple(AppInstallSessionPhase.FAILED, ControlCode.RUNTIME_FAILED, AppUpdatePhase.FAILED),
            Triple(AppInstallSessionPhase.CANCELLED, ControlCode.CANCELLED, AppUpdatePhase.IDLE),
            Triple(AppInstallSessionPhase.UNKNOWN, ControlCode.OUTCOME_UNKNOWN, AppUpdatePhase.IDLE),
        )) {
            val f = Fixture(backgroundScope)
            f.prepare()
            val status = AppInstallSessionStatus("receipt", phase, "2.2.0", false)
            val install = AndroidUpdateInstallControl(f.engine, f.interactions, pin = {
                object : AndroidUpdateInstallControl.Pinned {
                    override val version = "2.2.0"
                    override suspend fun verify() {}
                    override suspend fun prepareDispatch() {
                        f.engine.installSessionChanged(status)
                        error("No pending confirmation")
                    }
                    override fun snapshot() = AndroidUpdateInstallControl.PinnedState(status, mapOf(
                        "installed" to when (phase) {
                            AppInstallSessionPhase.INSTALLED -> ControlValue.BooleanValue(true)
                            AppInstallSessionPhase.FAILED, AppInstallSessionPhase.CANCELLED -> ControlValue.BooleanValue(false)
                            else -> ControlValue.Null
                        }))
                    override fun dispatch(launcher: (android.content.Intent) -> Unit) { error("No confirmation") }
                    override fun release(handedOff: Boolean) {}
                }
            })
            val work = async { install.execute("terminal-$phase") { true } }
            runCurrent()
            val token = requireNotNull(f.interactions.tokenFor("terminal-$phase"))
            val session = requireNotNull(f.interactions.attach(token, "owner", null))
            assertFalse(install.dispatch(token, session) {})
            val result = work.await()
            assertEquals(code, result.code)
            assertEquals(outer, f.state.phase)
            assertEquals(status, f.state.installSession)
            assertFalse(f.engine.busy())
        }
    }

    @Test fun recoveredHandoffAndFailureAreProjectedWithoutInventingCheckedManifest() = runTest {
        val f = Fixture(backgroundScope)
        val pending = AppInstallSessionStatus("recovered", AppInstallSessionPhase.HANDED_OFF, "2.2.0", true)
        f.engine.installSessionChanged(pending)
        val ticket = requireNotNull(f.engine.reserveRecoveredInstallation())
        f.engine.finishRecoveredInstallation(ticket, handedOff = true)
        assertEquals(AppUpdatePhase.INSTALLING, f.state.phase)
        f.engine.installSessionChanged(pending.copy(phase = AppInstallSessionPhase.FAILED, resumable = false))
        assertEquals(AppUpdatePhase.FAILED, f.state.phase)
        assertNull(f.engine.checkedStatus())
    }

    @Test fun cancellationDuringVerificationCannotPrepareAnInstallerAfterRetiringItsInteraction() = runTest {
        val f = Fixture(backgroundScope)
        val entered = CompletableDeferred<Unit>()
        val resume = CompletableDeferred<Unit>()
        var preparations = 0
        val install = AndroidUpdateInstallControl(f.engine, f.interactions, recover = {
            object : AndroidUpdateInstallControl.Pinned {
                override val version = "2.2.0"
                override suspend fun verify() { entered.complete(Unit); resume.await() }
                override suspend fun prepareDispatch() { preparations++ }
                override fun dispatch(launcher: (android.content.Intent) -> Unit) { error("Cancelled") }
                override fun release(handedOff: Boolean) {}
            }
        }, pin = { error("No new session") })
        val work = async { install.execute("cancel-during-verify") { true } }
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor("cancel-during-verify"))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        val dispatch = async { install.dispatch(token, session) {} }
        entered.await()
        install.cancel("cancel-during-verify")
        assertEquals(ControlCode.CANCELLED, work.await().code)
        resume.complete(Unit)
        assertFalse(dispatch.await())
        assertEquals(0, preparations)
    }

    @Test fun commitWithoutConfirmationIsNotHandoffAndRetainsUnknownReceipt() = runTest {
        val f = Fixture(backgroundScope)
        var committed = false
        var abandoned = false
        val install = AndroidUpdateInstallControl(f.engine, f.interactions, recover = {
            object : AndroidUpdateInstallControl.Pinned {
                override val version = "2.2.0"
                override suspend fun verify() {}
                override suspend fun prepareDispatch() { committed = true; error("INSTALL_OUTCOME_UNKNOWN") }
                override fun dispatch(launcher: (android.content.Intent) -> Unit) { error("No confirmation") }
                override fun release(handedOff: Boolean) { abandoned = !committed }
                override fun snapshot() = AndroidUpdateInstallControl.PinnedState(
                    AppInstallSessionStatus("receipt", AppInstallSessionPhase.COMMITTING, version, false),
                    mapOf("installPhase" to ControlValue.Text("committing")))
            }
        }, pin = { error("No new session") })
        val work = async { install.execute("unknown") { true } }
        runCurrent()
        val token = requireNotNull(f.interactions.tokenFor("unknown"))
        val session = requireNotNull(f.interactions.attach(token, "owner", null))
        assertFalse(install.dispatch(token, session) {})
        val result = work.await()
        assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
        assertEquals(ControlValue.BooleanValue(false), result.data["installerStarted"])
        assertEquals(ControlValue.Null, result.data["installed"])
        assertEquals(ControlValue.Text("committing"), result.data["installPhase"])
        assertFalse(abandoned)
    }
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
