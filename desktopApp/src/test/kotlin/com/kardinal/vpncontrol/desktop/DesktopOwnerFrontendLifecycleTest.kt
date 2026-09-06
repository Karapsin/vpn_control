package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopOwnerFrontendLifecycleTest {
    private val frontend = UUID.randomUUID().toString()
    private fun command(action: DesktopFrontendLeaseAction, id: String = frontend, owner: String = "owner") =
        DesktopCliCommand.ControlFrontendLease(UUID.randomUUID().toString(), owner, id, action)
    private fun code(response: DesktopCliResponse) = ControlProtocolCodec.decodeResult(response.message).code

    @Test fun leaseIsBoundedExclusiveAndCannotBeRenewedAfterExpiry() = runTest {
        var now = 0L
        var starts = 0
        val lifecycle = DesktopOwnerFrontendLifecycle("owner", backgroundScope, { starts++ },
            { DesktopControlMetadata(7, false) }, { now })
        assertFalse(lifecycle.hasOwnedWork()) // Queries alone do not initialize reconnect.
        assertEquals(ControlCode.CONFLICT, code(lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH, owner = "old"))))
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH))))
        runCurrent()
        assertEquals(1, starts)
        assertEquals(ControlCode.BUSY, code(lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH, UUID.randomUUID().toString()))))
        assertEquals(ControlCode.CONFLICT, code(lifecycle.execute(command(DesktopFrontendLeaseAction.DETACH, UUID.randomUUID().toString()))))
        assertTrue(lifecycle.hasOwnedWork())
        now = 14_999
        assertTrue(lifecycle.hasOwnedWork())
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.HEARTBEAT))))
        now += 15_000
        assertFalse(lifecycle.hasOwnedWork())
        assertEquals(ControlCode.NOT_FOUND, code(lifecycle.execute(command(DesktopFrontendLeaseAction.HEARTBEAT))))
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH))))
        runCurrent()
        assertEquals(1, starts)
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.DETACH))))
        assertFalse(lifecycle.hasOwnedWork())
    }

    @Test fun callerCancellationAndDetachDoNotCancelOnceOnlyOwnerInitialization() = runTest {
        var starts = 0
        val complete = CompletableDeferred<Unit>()
        val lifecycle = DesktopOwnerFrontendLifecycle("owner", backgroundScope, { starts++; complete.await() },
            { DesktopControlMetadata(0, false) })
        val caller = launch { lifecycle.resumeOnce() }
        runCurrent()
        caller.cancelAndJoin()
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH))))
        assertEquals(ControlCode.OK, code(lifecycle.execute(command(DesktopFrontendLeaseAction.DETACH))))
        assertTrue(lifecycle.hasOwnedWork())
        assertEquals(1, starts)
        complete.complete(Unit)
        runCurrent()
        assertFalse(lifecycle.hasOwnedWork())
        lifecycle.resumeOnce()
        assertEquals(1, starts)
    }

    @Test fun protocolRejectsInvalidIdentitiesAndNoLeaseEnablesPublicCommands() {
        for (action in DesktopFrontendLeaseAction.entries) {
            val valid = command(action)
            assertTrue(valid.bypassesMutationAdmission) // Native work cannot starve heartbeat/cancellation transport.
            assertEquals(valid, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(valid)).getOrThrow())
            val invalid = valid.copy(frontendId = "../../private")
            assertTrue(DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(invalid)).isFailure)
        }
    }

    @Test fun detachedOrExpiredFrontendNeverOverridesRuntimeOrJobRetention() = runTest {
        var now = 0L
        val lifecycle = DesktopOwnerFrontendLifecycle("owner", backgroundScope, {}, { DesktopControlMetadata(0, false) }, { now })
        val idle = DesktopOwnerIdlePolicy(false, { now })
        lifecycle.execute(command(DesktopFrontendLeaseAction.ATTACH)); runCurrent()
        now = 100_000
        assertFalse(lifecycle.hasOwnedWork())
        assertFalse(idle.shouldExit(hasWork = true)) // Active runtime or accepted job remains owner work.
        now += 29_999
        assertFalse(idle.shouldExit(hasWork = false))
        now++
        assertTrue(idle.shouldExit(hasWork = false))
    }
}
