package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.data.VpnCommandException
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidConnectionActionsServiceTest {
    @Test fun onVpnPermissionGrantedUpdatesControllerState() = AndroidGuiOwnerActionFixture().use { f ->
        f.controller.update { it.copy(hasVpnPermission = false) }
        f.connectionService().onVpnPermissionGranted()
        assertTrue(f.controller.currentState().hasVpnPermission)
    }

    @Test fun connectionGuiOffHasQueryableOwnerOperation() = AndroidGuiOwnerActionFixture(running = true).use { f ->
        f.connectionService().toggleVpn()
        assertEquals(1, f.stops) // The genuine GUI callback reached its effect boundary.
        assertEquals(AndroidRuntimeKnowledge.STOPPED, f.observer.state.value.knowledge)
        assertEquals("GUI OFF must enter the real owner ledger", 1, f.operations().size)
        val result = f.results.single()
        assertEquals(ControlCode.OK, result.code)
        assertEquals(ControlOperationId.OFF, f.requests.single().command.operation)
        assertEquals(result.copy(requestId = "observed"), f.status(requireNotNull(result.operationId)).copy(requestId = "observed"))
        assertFalse(f.jobs.busy.value)
    }

    @Test fun guiOnCommitsThroughRealSerializerAndKeepsQueryableResult() = AndroidGuiOwnerActionFixture().use { f ->
        f.connectionService().toggleVpn()
        assertEquals(1, f.starts)
        assertEquals(1, f.persists)
        assertEquals(1, f.operations().size)
        assertEquals(ControlCode.OK, f.results.single().code)
        assertEquals(f.snapshot().value.selectedProfileJson, f.coldReadSelectedProfile())
        assertFalse(f.results.single().restartRequired)
        assertEquals(listOf(MainCommandLogic.startedConnectionStatus(AppMode.VPN)), f.statuses)
    }

    @Test fun authoritativeRuntimeSelectsOffDespiteStaleFrontendAndRetainsPendingSettings() = AndroidGuiOwnerActionFixture(running = true).use { f ->
        f.controller.update { it.copy(isVpnRunning = false) }
        f.changeMode(AppMode.PROXY_ONLY)
        val configuration = f.snapshot()
        f.connectionService().toggleVpn()
        assertEquals(0, f.starts)
        assertEquals(1, f.stops)
        assertEquals(ControlOperationId.OFF, f.requests.single().command.operation)
        assertEquals(configuration, f.snapshot())
        assertEquals(listOf(MainCommandLogic.stoppedConnectionStatus(AppMode.VPN)), f.statuses)
    }

    @Test fun missingConsentOrForegroundCannotPrepareOrStart() {
        for (missingForeground in listOf(false, true)) AndroidGuiOwnerActionFixture().use { f ->
            if (missingForeground) f.foreground = false else f.vpnPrepared = false
            f.connectionService().toggleVpn()
            assertEquals(ControlCode.INTERACTION_REQUIRED, f.results.single().code)
            assertFalse(f.requests.single().interactive)
            assertEquals(0, f.starts)
            assertEquals(0, f.persists)
            assertTrue(f.operations().isEmpty())
            assertEquals(listOf(ConnectionStatusMessages.connectionStartFailed(AppMode.VPN)), f.statuses)
        }
    }

    @Test fun busyOrStaleAdmissionHasNoConnectionEffects() {
        AndroidGuiOwnerActionFixture().use { f ->
            val lease = requireNotNull(f.jobs.tryAcquireMutation())
            try {
                f.connectionService().toggleVpn()
                assertEquals(ControlCode.BUSY, f.results.single().code)
                assertEquals(0, f.starts)
                assertTrue(f.operations().isEmpty())
            } finally { f.jobs.releaseMutation(lease) }
        }
        AndroidGuiOwnerActionFixture().use { f ->
            f.beforeExecute = { f.changeMode(AppMode.PROXY_ONLY) }
            f.connectionService().toggleVpn()
            assertEquals(ControlCode.CONFLICT, f.results.single().code)
            assertEquals(0, f.starts)
            assertEquals(AppMode.PROXY_ONLY, f.snapshot().value.appMode)
        }
    }

    @Test fun cancelledFrontendWaitDoesNotCancelOwnerAndRetryCannotToggleNewRuntimeOff() = runTest {
        AndroidGuiOwnerActionFixture().use { f ->
            f.frontendLaunch = { block -> f.frontendJobs += launch { block() } }
            val release = CompletableDeferred<Unit>()
            f.nativeGate = release
            val service = f.connectionService()
            service.toggleVpn()
            runCurrent()
            val request = f.requests.single()
            val id = requireNotNull(f.owner.operationIdForRequest(request.requestId))
            assertEquals(1, f.starts)
            assertTrue(f.jobs.busy.value)
            assertFalse(f.status(id).final)
            service.toggleVpn() // Duplicate gesture cannot enter another operation.
            assertEquals(1, f.requests.size)
            f.frontendJobs.single().cancelAndJoin()
            assertTrue(f.jobs.busy.value)
            release.complete(Unit)
            assertEquals(ControlCode.OK, f.status(id, wait = true).code)
            assertFalse(f.jobs.busy.value)
            service.toggleVpn()
            runCurrent()
            f.frontendJobs.last().join()
            assertEquals(request, f.requests.last())
            assertEquals(1, f.starts)
            assertEquals(0, f.stops)
            assertEquals(1, f.persists)
            assertEquals(1, f.operations().size)
        }
    }

    @Test fun lostResponseRetriesOneOwnerIdentityWithoutDuplicateEffects() = AndroidGuiOwnerActionFixture(running = true).use { f ->
        val service = f.connectionService()
        f.loseResponse = true
        service.toggleVpn()
        assertEquals(1, f.stops)
        assertEquals(listOf(ConnectionStatusMessages.connectionStopFailed(AppMode.VPN)), f.statuses)
        service.toggleVpn()
        assertEquals(f.requests.first(), f.requests.last())
        assertEquals(1, f.operations().size)
        assertEquals(1, f.stops)
        assertEquals(0, f.starts)
        assertEquals(MainCommandLogic.stoppedConnectionStatus(AppMode.VPN), f.statuses.last())
    }

    @Test fun dispatchUncertaintyAndPersistenceFailureNeverPublishSuccess() {
        AndroidGuiOwnerActionFixture(running = true).use { f ->
            val before = f.observer.state.value
            f.nativeFailure = VpnCommandException("PRIVATE unknown dispatch", cause = AndroidRuntimeOutcomeUnknownException(), commandDispatched = true)
            val service = f.connectionService()
            service.toggleVpn()
            assertEquals(ControlCode.RUNTIME_FAILED, f.results.single().code)
            assertTrue("RUNTIME_OUTCOME_UNKNOWN" in f.results.single().warnings)
            assertEquals(before, f.observer.state.value)
            assertEquals(listOf(ConnectionStatusMessages.connectionStopFailed(AppMode.VPN)), f.statuses)
            service.toggleVpn()
            assertEquals(f.requests.first(), f.requests.last())
            assertEquals(1, f.stops)
            assertEquals(1, f.operations().size)
        }
        AndroidGuiOwnerActionFixture().use { f ->
            f.failPersist = true
            f.connectionService().toggleVpn()
            assertEquals(ControlCode.RUNTIME_FAILED, f.results.single().code)
            assertTrue("RUNTIME_STARTED_PERSISTENCE_FAILED" in f.results.single().warnings)
            assertEquals(AndroidRuntimeKnowledge.RUNNING, f.observer.state.value.knowledge)
            assertEquals(0, f.persists)
            assertEquals(listOf(ConnectionStatusMessages.connectionStartFailed(AppMode.VPN)), f.statuses)
        }
    }
}
