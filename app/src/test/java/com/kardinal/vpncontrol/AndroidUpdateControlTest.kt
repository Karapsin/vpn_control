package com.kardinal.vpncontrol

import java.io.File
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidUpdateControlTest {
    @Test fun reservedCancellationCannotRetargetANewerTransferAfterOldWorkerCompletes() = runTest {
        var state = AppUpdateState()
        val fetched = CompletableDeferred<UpdateManifest>()
        var checks = 0
        val control = AndroidUpdateControl({ backgroundScope.launch { it() } }, "1.0.0", 10,
            { checks++; if (checks == 1) fetched.await() else manifest }, { asset }, { File("synthetic") },
            { _, _, _ -> }, {}, {}, { state = it(state) })
        val first = async { control.check() }
        runCurrent()
        val ticket = requireNotNull(control.reserveCancellation())
        fetched.complete(manifest)
        assertTrue(first.await().isSuccess)
        // The original worker has finished, but the admitted cancellation continuation
        // has not run. Its reserved gate prevents a different transfer from entering.
        assertEquals("BUSY", control.check().exceptionOrNull()?.message)
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.OK, control.finishCancellation(ticket).code)
        assertTrue(control.check().isSuccess)
        assertEquals(2, checks)
    }
    @Test fun completedUnsupportedCheckRetainsItsOutcomeWhenDismissRunsBeforeWaiterResumes() = runTest {
        val workerScope = CoroutineScope(SupervisorJob() + UnconfinedTestDispatcher(testScheduler))
        val fetched = CompletableDeferred<UpdateManifest>()
        var state = AppUpdateState()
        val control = AndroidUpdateControl({ workerScope.launch { it() } }, "1.0.0", 10,
            { fetched.await() }, { null }, { error("No download") }, { _, _, _ -> }, {}, {}, { state = it(state) })
        val check = async { control.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK) }
        runCurrent()
        fetched.complete(manifest)
        assertFalse(control.busy())
        assertFalse(check.isCompleted)
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.OK,
            control.execute(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DISMISS).code)
        val completed = check.await()
        assertEquals(com.kardinal.vpncontrol.model.ControlCode.UNSUPPORTED, completed.code)
        assertEquals(com.kardinal.vpncontrol.model.ControlValue.Text("unsupported"), completed.data["phase"])
        assertEquals(com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true), completed.data["available"])
        assertEquals(AppUpdatePhase.IDLE, state.phase)
        workerScope.cancel()
    }
    private val asset = UpdateAsset(UpdatePlatform.ANDROID, "arm64-v8a", UpdatePackageType.APK, "2.2.0", "update.apk",
        "https://github.com/synthetic/update.apk", "a".repeat(64), 10)
    private val manifest get() = UpdateManifest(1, 20, "v2.2.0", "https://github.com/synthetic", listOf(asset))

    @Test fun checkDoesNotDownloadAndDownloadUsesExactCheckedManifest() = runTest {
        var state = AppUpdateState()
        var checks = 0; var downloads = 0; var verified = 0
        val control = AndroidUpdateControl({ backgroundScope.launch { it() } }, "1.0.0", 10,
            { checks++; manifest }, { it.assets.single() }, { downloads++; File("synthetic.apk") },
            { _, selected, build -> assertEquals(asset, selected); assertEquals(20, build); verified++ }, {}, {}, { state = it(state) })
        assertTrue(control.check().isSuccess)
        assertEquals(1, checks); assertEquals(0, downloads); assertEquals(AppUpdatePhase.IDLE, state.phase)
        assertTrue(requireNotNull(control.checkedStatus()).available)
        assertNull(control.preparedFile)
        assertTrue(control.downloadChecked().isSuccess)
        assertEquals(1, checks); assertEquals(1, downloads); assertEquals(1, verified)
        assertEquals(AppUpdatePhase.READY, state.phase)
    }

    @Test fun cancellationKeepsBusyUntilCleanupAndDisconnectedWaiterDoesNotCancelTransfer() = runTest {
        var state = AppUpdateState()
        val entered = CompletableDeferred<Unit>(); val cleanupEntered = CompletableDeferred<Unit>(); val cleanupRelease = CompletableDeferred<Unit>()
        var cleanupCount = 0
        val control = AndroidUpdateControl({ backgroundScope.launch { it() } }, "1.0.0", 10,
            { entered.complete(Unit); awaitCancellation() }, { asset }, { error("No download") }, { _, _, _ -> },
            { cleanupCount++; cleanupEntered.complete(Unit); cleanupRelease.await() }, {}, { state = it(state) })
        val waiter = launch { control.check() }
        entered.await(); waiter.cancelAndJoin()
        assertTrue(control.busy()); assertEquals(AppUpdatePhase.CHECKING, state.phase)
        val cancelled = async { control.cancel(dismiss = true) }
        cleanupEntered.await()
        assertFalse(cancelled.isCompleted); assertTrue(control.busy())
        assertEquals("BUSY", control.check().exceptionOrNull()?.message)
        cleanupRelease.complete(Unit)
        assertTrue(cancelled.await().isSuccess); assertFalse(control.busy())
        assertEquals(AppUpdatePhase.IDLE, state.phase); assertFalse(state.showDialog)
        assertTrue(cleanupCount >= 1)
    }

    @Test fun closedOwnerScopeAndVerificationFailureCannotProduceReadyPackage() = runTest {
        var state = AppUpdateState()
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val control = AndroidUpdateControl({ scope.launch { it() } }, "1.0.0", 10,
            { manifest }, { asset }, { File("synthetic.apk") }, { _, _, _ -> error("PRIVATE_PATH") }, {}, {}, { state = it(state) })
        assertTrue(control.check().isSuccess)
        assertTrue(control.downloadChecked().isFailure)
        assertEquals(AppUpdatePhase.FAILED, state.phase); assertFalse(state.message.contains("PRIVATE_PATH")); assertNull(control.preparedFile)
        scope.cancel()
        assertTrue(control.check().isFailure); assertFalse(control.busy())
    }
}
