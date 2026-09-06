package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopGuiOwnerConnectionTest {
    @Test fun pinnedGuiStartupNeverStartsAReplacementOwner() = runTest {
        val epoch = UUID.randomUUID().toString()
        val result = DesktopGuiOwnerConnection.connect(backgroundScope, UUID.randomUUID().toString(),
            expectedOwnerId = epoch, request = {
                assertEquals(epoch, (it as DesktopCliCommand.ControlSnapshotRead).controllerId)
                DesktopCliResponse.notRunning()
            }, startOwner = { error("pinned GUI must not restart vanished owner") })
        assertEquals(ControlCode.UNAVAILABLE, (result.exceptionOrNull() as ControlProtocolException).code)
    }

    @Test fun stalledDiscoveryTimesOutWithoutStartingOwner() = runTest {
        var starts = 0
        val result = DesktopGuiOwnerConnection.connect(backgroundScope, UUID.randomUUID().toString(),
            request = { awaitCancellation() }, startOwner = { starts++; error("must not start") })
        assertEquals(ControlCode.TIMEOUT, (result.exceptionOrNull() as ControlProtocolException).code)
        assertEquals(0, starts)
    }

    @Test fun authenticatedOwnerEndpointAdmitsLeaseAndCloseDoesNotStopOwner() = runBlocking {
        val directory = Files.createTempDirectory("gui-owner-authenticated")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(), emptyList())))
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } }, controllerId = owner.controllerId, portFile = endpoint))
        val clients = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val client = DesktopGuiOwnerConnection.connect(clients, UUID.randomUUID().toString(), request = {
                withContext(Dispatchers.IO) { DesktopActivationServer.requestCliCommand(it, endpoint) }
            }, startOwner = { error("existing authenticated owner must be reused") }).getOrThrow()
            assertEquals(owner.controllerId, client.session.snapshots.value.controllerId)
            assertFalse(client.session.presentations.value!!.frontend.runtime.runtimeRunning)
            client.close()
            withTimeout(5_000) { while (owner.frontends.hasOwnedWork()) delay(10) }
            assertTrue(DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSnapshotRead(owner.controllerId), endpoint).success)
        } finally { clients.cancel(); server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun transportFailuresNeverBootstrapAnotherOwner() = runTest {
        for (failure in listOf(DesktopCliResponse.failure("PERMISSION_DENIED"),
            DesktopCliResponse.failure("TIMEOUT", 2), DesktopCliResponse.failure("INCOMPATIBLE_PROTOCOL", 2))) {
            var starts = 0
            val result = DesktopGuiOwnerConnection.connect(backgroundScope, UUID.randomUUID().toString(),
                request = { failure }, startOwner = { starts++; error("must not start") })
            assertTrue(result.isFailure)
            assertEquals(0, starts)
        }
    }

    @Test fun exactNotRunningBootstrapsAndDetachLeavesDisconnectedOwnerIntact() = runTest {
        val directory = Files.createTempDirectory("gui-owner-connect")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(), emptyList())), scope = backgroundScope)
        var running = false
        var starts = 0
        val commands = mutableListOf<DesktopCliCommand>()
        val client = DesktopGuiOwnerConnection.connect(backgroundScope, UUID.randomUUID().toString(), request = {
            commands += it
            if (running) owner.execute(it) else DesktopCliResponse.notRunning()
        }, startOwner = { starts++; running = true; owner.execute(it) }).getOrThrow()
        try {
            assertEquals(1, starts)
            assertNotNull(client.session.presentations.value?.frontend)
            assertTrue(owner.frontends.hasOwnedWork())
            advanceTimeBy(5_000); runCurrent()
            assertTrue(commands.filterIsInstance<DesktopCliCommand.ControlFrontendLease>().any { it.action == DesktopFrontendLeaseAction.HEARTBEAT })
            client.close(); runCurrent()
            assertFalse(owner.frontends.hasOwnedWork())
            assertFalse(owner.service.state.isVpnRunning)
            assertTrue(owner.execute(DesktopCliCommand.ControlSnapshotRead(owner.controllerId)).success)
        } finally { client.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun rejectedHeartbeatClosesClientWithoutReattachOrOwnerRestart() = runTest {
        val directory = Files.createTempDirectory("gui-owner-lease-loss")
        val ownerScope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(), emptyList())), scope = ownerScope)
        var attaches = 0
        var starts = 0
        val client = DesktopGuiOwnerConnection.connect(backgroundScope, UUID.randomUUID().toString(), request = {
            if (it is DesktopCliCommand.ControlFrontendLease && it.action == DesktopFrontendLeaseAction.ATTACH) attaches++
            if (it is DesktopCliCommand.ControlFrontendLease && it.action == DesktopFrontendLeaseAction.HEARTBEAT)
                DesktopCliResponse.failure("CONFLICT") else owner.execute(it)
        }, startOwner = { starts++; error("must not start") }).getOrThrow()
        try {
            advanceTimeBy(5_000); runCurrent()
            assertEquals(ControlCode.CONFLICT, client.failure.value)
            assertEquals(ControlCode.UNAVAILABLE, client.session.connectionFailure.value)
            assertEquals(1, attaches)
            assertEquals(0, starts)
        } finally { client.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
