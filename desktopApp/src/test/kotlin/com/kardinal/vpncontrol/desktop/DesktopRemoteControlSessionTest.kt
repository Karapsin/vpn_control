package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlin.test.*

class DesktopRemoteControlSessionTest {
    @Test fun closingWhileAReadIsInFlightCannotRestoreLiveConnectionState() = runTest {
        val initial = ControlSnapshot("owner", 1, null, null, AppMode.PROXY_ONLY, null, null, null, false)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var block = false
        val remote = DesktopRemoteControlSession.connect(backgroundScope, {
            if (block) { entered.complete(Unit); release.await() }
            DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlSnapshotCodec.encode(initial))
        }, 60_000).getOrThrow()
        block = true
        val pending = async { remote.refresh() }
        entered.await()
        remote.close()
        release.complete(Unit)
        assertTrue(pending.await().isFailure)
        assertEquals(ControlCode.UNAVAILABLE, remote.connectionFailure.value)
        assertEquals(ControlCode.UNAVAILABLE, remote.presentationFailure.value)
        assertEquals(initial, remote.snapshots.value)
        assertTrue(backgroundScope.isActive)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun presentationPollingRetainsLastGoodStateAndNeverAcceptsOwnerOrRevisionReplacement() = runTest {
        val directory = Files.createTempDirectory("presentation-decoder")
        val fixture = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(appMode = AppMode.PROXY_ONLY), emptyList()))
        val presentationValues = fixture.controlPresentationSnapshot("owner").values
        val initial = ControlSnapshot("owner", 1, null, null, AppMode.PROXY_ONLY, null, null, null, false)
        var revision = 1L
        var epoch = "owner"
        var malformedLocations = false
        val remote = DesktopRemoteControlSession.connect(backgroundScope, { command ->
            when (command) {
                is DesktopCliCommand.ControlSnapshotRead -> DesktopCliResponse.success(
                    com.kardinal.vpncontrol.control.ControlSnapshotCodec.encode(initial.copy(configurationRevision = revision)))
                is DesktopCliCommand.ControlPresentationRead -> {
                    assertEquals("owner", command.controllerId)
                    val values = presentationValues +
                        (if (malformedLocations) mapOf("locations" to ControlValue.ArrayValue(listOf(
                            ControlValue.ObjectValue(mapOf("rawLink" to ControlValue.Text("PRIVATE_PROFILE")))))) else emptyMap())
                    DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(
                        ControlResult(epoch, command.requestId, ControlCode.OK, revision, data = values)))
                }
                else -> error("Unexpected command")
            }
        }, pollPresentation = true).getOrThrow()
        try {
            runCurrent()
            assertNull(remote.presentations.value)
            advanceTimeBy(500)
            runCurrent()
            assertEquals(1L, remote.presentations.value?.configurationRevision)
            revision = 2
            advanceTimeBy(500)
            runCurrent()
            assertEquals(2L, remote.presentations.value?.configurationRevision)
            val lastGood = remote.presentations.value
            malformedLocations = true
            assertTrue(remote.presentation().isFailure)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, remote.presentationFailure.value)
            assertEquals(lastGood, remote.presentations.value)
            malformedLocations = false
            revision = 1
            assertTrue(remote.presentation().isFailure)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, remote.presentationFailure.value)
            assertEquals(2L, remote.presentations.value?.configurationRevision)
            revision = 2
            epoch = "replacement"
            assertTrue(remote.presentation().isFailure)
            assertEquals(ControlCode.CONFLICT, remote.presentationFailure.value)
            assertEquals("owner", remote.presentations.value?.controllerId)
        } finally { remote.close(); directory.toFile().deleteRecursively() }
        assertEquals(ControlCode.UNAVAILABLE, remote.presentationFailure.value)
        assertTrue(backgroundScope.isActive)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    @Test fun pollingPublishesNewSnapshotsButRejectsRevisionRollbackAndMalformedFrames() = runTest {
        val initial = ControlSnapshot("owner", 1, null, null, AppMode.PROXY_ONLY, null, null, null, false)
        var observed = initial
        var malformed = false
        val remote = DesktopRemoteControlSession.connect(backgroundScope, {
            DesktopCliResponse.success(if (malformed) "private malformed payload" else
                com.kardinal.vpncontrol.control.ControlSnapshotCodec.encode(observed))
        }).getOrThrow()
        try {
            runCurrent()
            observed = initial.copy(configurationRevision = 2)
            advanceTimeBy(500)
            runCurrent()
            assertEquals(2L, remote.snapshots.value.configurationRevision)
            assertNull(remote.connectionFailure.value)
            observed = initial
            assertTrue(remote.refresh().isFailure)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, remote.connectionFailure.value)
            assertEquals(2L, remote.snapshots.value.configurationRevision)
            malformed = true
            assertTrue(remote.refresh().isFailure)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, remote.connectionFailure.value)
            assertFalse(remote.snapshots.value.toString().contains("private malformed payload"))
        } finally { remote.close() }
        assertTrue(backgroundScope.isActive)
    }

    @Test fun authenticatedClientsObserveOneOwnerAndDetachingDoesNotStopIt() = runBlocking {
        val directory = Files.createTempDirectory("remote-control-session")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId))
        val clients = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        suspend fun request(command: DesktopCliCommand): DesktopCliResponse = withContext(Dispatchers.IO) {
            DesktopActivationServer.requestCliCommand(command, endpoint)
        }
        val first = DesktopRemoteControlSession.connect(clients, ::request, 60_000).getOrThrow()
        val second = DesktopRemoteControlSession.connect(clients, ::request, 60_000).getOrThrow()
        try {
            assertEquals(owner.controllerId, first.snapshots.value.controllerId)
            assertEquals(first.snapshots.value, second.snapshots.value)
            val request = ControlRequest("write", ControlCommand(ControlOperationId.SETTINGS_SET,
                mapOf("key" to ControlValue.Text("validation.batch-size"), "value" to ControlValue.Text("7"))))
            val saved = first.submit(request)
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(1L, saved.configurationRevision)
            assertEquals(1L, second.refresh().getOrThrow().configurationRevision)
            assertEquals(ControlOperationPhase.SUCCEEDED, second.operation(requireNotNull(saved.operationId))?.phase)
            first.close()
            assertEquals(ControlCode.UNAVAILABLE, first.submit(request).code)
            assertTrue(clients.isActive)
            assertEquals(saved, second.submit(request))
            assertEquals(1L, owner.service.configurationRevision)
            assertEquals(ControlCode.NOT_FOUND, second.cancelOperation("missing").code)
            server.close()
            assertTrue(second.refresh().isFailure)
            assertNotNull(second.connectionFailure.value)
            assertEquals(1L, second.snapshots.value.configurationRevision) // Explicitly stale, not invented off.
        } finally { first.close(); second.close(); clients.cancel(); server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun ownerReplacementNeverRebindsOrReplaysWrites() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        var epoch = "first-owner"
        var writes = 0
        val initial = ControlSnapshot(epoch, 0, null, null, AppMode.PROXY_ONLY, null, null, null, false)
        val remote = DesktopRemoteControlSession.connect(scope, { command ->
            when (command) {
                is DesktopCliCommand.ControlSnapshotRead -> DesktopCliResponse.success(
                    com.kardinal.vpncontrol.control.ControlSnapshotCodec.encode(initial.copy(controllerId = epoch)))
                is DesktopCliCommand.ControlSubmit -> {
                    assertEquals("first-owner", command.request.controllerId)
                    if (command.request.controllerId == epoch) writes++
                    DesktopCliResponse.failure("CONFLICT")
                }
                else -> error("Unexpected command")
            }
        }, 60_000).getOrThrow()
        try {
            epoch = "replacement"
            assertTrue(remote.refresh().isFailure)
            assertEquals(ControlCode.CONFLICT, remote.connectionFailure.value)
            assertEquals("first-owner", remote.snapshots.value.controllerId)
            remote.submit(ControlRequest("write", ControlCommand(ControlOperationId.OFF)))
            assertEquals(0, writes)
        } finally { remote.close(); scope.cancel() }
    }
}
