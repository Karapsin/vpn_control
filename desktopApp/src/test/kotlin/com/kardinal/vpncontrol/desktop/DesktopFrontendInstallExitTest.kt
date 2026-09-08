package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlValue
import java.util.UUID
import kotlin.test.*

class DesktopFrontendInstallExitTest {
    @Test fun acknowledgementIsFramedBeforeExactlyOneExitDelivery() {
        val queued = mutableListOf<() -> Unit>()
        var exits = 0
        val fixture = fixture(dispatch = { queued += it }, handler = { exits++ })
        val response = fixture.exit.execute(fixture.command, fixture.identity)
        assertTrue(response.success)
        assertEquals(0, exits)
        fixture.exit.responseFlushed(fixture.command, response)
        assertEquals(0, exits)
        assertEquals(1, queued.size)
        queued.single().invoke()
        fixture.exit.responseFlushed(fixture.command, response)
        assertEquals(1, exits)
    }

    @Test fun unsafeOrMismatchedRequestsNeverAcknowledgeOrExit() {
        val queued = mutableListOf<() -> Unit>()
        var exits = 0
        val fixture = fixture(dispatch = { queued += it }, handler = { exits++ })
        val unsafe = fixture.command.copy(request = fixture.command.request.copy(interactive = true))
        val foreign = fixture.command.copy(request = fixture.command.request.copy(controllerId = uuid()))
        val wrongPid = fixture.command.copy(request = fixture.command.request.copy(command = fixture.command.request.command.copy(
            arguments = fixture.command.request.command.arguments + ("pid" to ControlValue.IntegerValue(fixture.identity.pid + 1)))))
        val original = fixture.command.request
        val malformed = listOf(
            original.copy(asynchronous = true), original.copy(ifRevision = 1), original.copy(requestId = "invalid"),
            original.copy(command = original.command.copy(arguments = original.command.arguments - "jobId")),
            original.copy(command = original.command.copy(arguments = original.command.arguments + ("extra" to ControlValue.Text("x")))),
            original.copy(command = original.command.copy(arguments = original.command.arguments + ("owner" to ControlValue.Text(uuid())))),
            original.copy(command = original.command.copy(arguments = original.command.arguments + ("jobId" to ControlValue.Text("invalid")))),
            original.copy(command = original.command.copy(arguments = original.command.arguments + ("startedAtEpochMillis" to ControlValue.IntegerValue(100)))),
        ).map { fixture.command.copy(request = it) }
        (listOf(unsafe, foreign, wrongPid) + malformed).forEach { assertFalse(fixture.exit.execute(it, fixture.identity).success) }
        fixture.exit.responseFlushed(fixture.command, DesktopCliResponse.success("malformed"))
        assertTrue(queued.isEmpty())
        assertEquals(0, exits)
    }

    @Test fun duplicateRetryIsIdempotentAndDifferentCorrelationIsRejected() {
        val queued = mutableListOf<() -> Unit>()
        var exits = 0
        val fixture = fixture(dispatch = { queued += it }, handler = { exits++ })
        val first = fixture.exit.execute(fixture.command, fixture.identity)
        val retry = fixture.exit.execute(fixture.command, fixture.identity)
        assertEquals(first, retry)
        val different = fixture.command.copy(request = fixture.command.request.copy(requestId = uuid()))
        assertFalse(fixture.exit.execute(different, fixture.identity).success)
        fixture.exit.responseFlushed(fixture.command, first)
        fixture.exit.responseFlushed(fixture.command, retry)
        assertEquals(1, queued.size)
        queued.single().invoke()
        assertEquals(1, exits)
    }

    @Test fun ownerChangeOrMissingHandlerPreventsDeliveryAndCanRetryAfterCallbackFailure() {
        val queued = mutableListOf<() -> Unit>()
        var owner: String? = uuid()
        var exits = 0
        val fixture = fixture(owner = { owner }, dispatch = { queued += it }, handler = { error("first callback fails") })
        val response = fixture.exit.execute(fixture.command, fixture.identity)
        fixture.exit.responseFlushed(fixture.command, response)
        queued.removeAt(0).invoke()
        fixture.exit.install { exits++ }
        fixture.exit.responseFlushed(fixture.command, response)
        queued.removeAt(0).invoke()
        assertEquals(1, exits)

        val second = fixture(owner = { owner }, dispatch = { queued += it }, handler = { exits++ })
        val accepted = second.exit.execute(second.command, second.identity)
        second.exit.responseFlushed(second.command, accepted)
        owner = uuid()
        queued.removeAt(0).invoke()
        assertEquals(1, exits)
        second.exit.responseFlushed(second.command, accepted)
        assertTrue(queued.isEmpty())

        val noHandler = fixture(owner = { owner }, dispatch = { queued += it }, handler = null)
        assertFalse(noHandler.exit.execute(noHandler.command, noHandler.identity).success)

        val vanished = fixture(owner = { owner }, dispatch = { queued += it }, handler = { exits++ })
        val vanishedResponse = vanished.exit.execute(vanished.command, vanished.identity)
        vanished.exit.responseFlushed(vanished.command, vanishedResponse)
        vanished.exit.install(null)
        queued.removeAt(0).invoke()
        vanished.exit.install { exits++ }
        vanished.exit.responseFlushed(vanished.command, vanishedResponse)
        queued.removeAt(0).invoke()
        assertEquals(2, exits)
    }

    private data class Fixture(
        val exit: DesktopFrontendInstallExit,
        val identity: DesktopFrontendProcessIdentity,
        val command: DesktopCliCommand.ControlSubmit,
    )

    private fun fixture(
        owner: (() -> String?)? = null,
        dispatch: ((() -> Unit) -> Unit),
        handler: (() -> Unit)?,
    ): Fixture {
        val ownerId = owner?.invoke() ?: uuid()
        val identity = DesktopFrontendProcessIdentity(uuid(), 42, 99)
        val command = DesktopCliCommand.ControlSubmit(ControlRequest(uuid(), ControlCommand(ControlOperationId.QUIT, mapOf(
            "owner" to ControlValue.Text(ownerId),
            "installOperation" to ControlValue.Text(uuid()),
            "jobId" to ControlValue.Text(uuid()),
            "pid" to ControlValue.IntegerValue(identity.pid),
            "startedAtEpochMillis" to ControlValue.IntegerValue(identity.startedAtEpochMillis),
        )), controllerId = identity.registrationId))
        return Fixture(DesktopFrontendInstallExit(owner ?: { ownerId }, dispatch).also { it.install(handler) }, identity, command)
    }

    private fun uuid(): String = UUID.randomUUID().toString()
}
