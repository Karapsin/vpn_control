package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopFrontendQuitExitTest {
    private val owner = UUID.randomUUID().toString()
    private val identity = DesktopFrontendProcessIdentity(UUID.randomUUID().toString(), 42, 99)
    private val publicRequestId = "supported public request with spaces"

    @Test fun exactAcknowledgementFlushesBeforeOneFrontendExitAndRetryIsIdempotent() {
        var exits = 0
        val receiver = DesktopFrontendQuitExit({ owner }, { it() }).apply { install { exits++ } }
        val command = command()
        val response = receiver.execute(command, identity)
        assertTrue(response.success)
        assertEquals(0, exits)
        receiver.responseFlushed(command, response)
        receiver.responseFlushed(command, response)
        assertEquals(1, exits)
        assertTrue(receiver.execute(command, identity).success)
        receiver.responseFlushed(command, response)
        assertEquals(1, exits)
    }

    @Test fun unsafeOrMismatchedNormalQuitCannotCloseFrontend() {
        var exits = 0
        val receiver = DesktopFrontendQuitExit({ owner }, { it() }).apply { install { exits++ } }
        val valid = command()
        val wrongOwner = command(owner = UUID.randomUUID().toString())
        val controlCharacter = command(publicRequestId = "bad\nrequest")
        val wrongPid = command(pid = identity.pid + 1)
        val wrongStart = command(started = identity.startedAtEpochMillis + 1)
        val wrongFrontend = command(controllerId = UUID.randomUUID().toString())
        val interactive = command().copy(request = command().request.copy(interactive = true))
        val revised = command().copy(request = command().request.copy(ifRevision = 1))
        for (candidate in listOf(wrongOwner, controlCharacter, wrongPid, wrongStart, wrongFrontend, interactive, revised))
            assertFalse(receiver.execute(candidate, identity).success)
        receiver.responseFlushed(valid, DesktopCliResponse.success("malformed"))
        assertEquals(0, exits)
    }

    @Test fun acceptedRequestRejectsDifferentCorrelationAndMismatchedEchoDoesNotExit() {
        var exits = 0
        val receiver = DesktopFrontendQuitExit({ owner }, { it() }).apply { install { exits++ } }
        val accepted = command()
        val response = receiver.execute(accepted, identity)
        assertTrue(response.success)
        assertFalse(receiver.execute(command(), identity).success)
        assertFalse(receiver.execute(command(publicRequestId = "another public request"), identity).success)
        val result = ControlProtocolCodec.decodeResult(response.message)
        val mismatched = DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result.copy(
            data = result.data + ("quitRequestId" to ControlValue.Text("another public request")))))
        receiver.responseFlushed(accepted, mismatched)
        assertEquals(0, exits)
        receiver.responseFlushed(accepted, response)
        assertEquals(1, exits)
    }

    @Test fun ownerChangeAfterQueuedDispatchAndThrownCallbackDoNotCreateFalseDelivery() {
        var expectedOwner = owner
        var queued: (() -> Unit)? = null
        var exits = 0
        val receiver = DesktopFrontendQuitExit({ expectedOwner }, { queued = it }).apply { install { exits++ } }
        val command = command()
        val response = receiver.execute(command, identity)
        receiver.responseFlushed(command, response)
        expectedOwner = UUID.randomUUID().toString()
        assertNotNull(queued).invoke()
        assertEquals(0, exits)

        expectedOwner = owner
        var attempts = 0
        val retry = DesktopFrontendQuitExit({ expectedOwner }, { it() }).apply {
            install { if (attempts++ == 0) error("callback failure") else exits++ }
        }
        val retryResponse = retry.execute(command, identity)
        retry.responseFlushed(command, retryResponse)
        assertEquals(0, exits)
        retry.responseFlushed(command, retryResponse)
        assertEquals(1, exits)
    }

    @Test fun senderRetainsExactRequestAcrossLossAndWrongAckButNeverTreatsUnknownAsGone() = runTest {
        val correlation = DesktopFrontendQuitCorrelation(owner, publicRequestId, identity)
        val sent = mutableListOf<DesktopCliCommand.ControlSubmit>()
        var observed = 0
        val sender = DesktopOwnerFrontendQuit(correlation, request = { command ->
            sent += command
            when (sent.size) {
                1 -> DesktopCliResponse.failure("OUTCOME_UNKNOWN", 2)
                2 -> DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(identity.registrationId,
                    command.request.requestId, ControlCode.OK, 0, data = mapOf("owner" to ControlValue.Text(owner)))))
                else -> DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(identity.registrationId,
                    command.request.requestId, ControlCode.OK, 0, data = command.request.command.arguments)))
            }
        }, observe = {
            if (observed++ == 0) DesktopFrontendProcessObservation.UNKNOWN else DesktopFrontendProcessObservation.SAME
        }, pause = {})
        sender.awaitAcknowledgement()
        assertEquals(3, sent.size)
        assertEquals(sent.first(), sent[1])
        assertEquals(sent.first(), sent.last())
    }

    @Test fun senderAcceptsCapturedGenerationGoneWithoutSendingAndPropagatesCancellation() = runTest {
        val correlation = DesktopFrontendQuitCorrelation(owner, publicRequestId, identity)
        var requests = 0
        DesktopOwnerFrontendQuit(correlation, request = { requests++; error("gone frontend must not be queried") },
            observe = { DesktopFrontendProcessObservation.GONE }).awaitAcknowledgement()
        assertEquals(0, requests)
        assertFailsWith<CancellationException> {
            DesktopOwnerFrontendQuit(correlation, request = { throw CancellationException() },
                observe = { DesktopFrontendProcessObservation.SAME }, pause = {}).awaitAcknowledgement()
        }
    }

    private fun command(
        owner: String = this.owner,
        publicRequestId: String = this.publicRequestId,
        pid: Long = identity.pid,
        started: Long = identity.startedAtEpochMillis,
        controllerId: String = identity.registrationId,
    ): DesktopCliCommand.ControlSubmit = DesktopCliCommand.ControlSubmit(ControlRequest(UUID.randomUUID().toString(),
        ControlCommand(ControlOperationId.QUIT, mapOf(
            "owner" to ControlValue.Text(owner),
            "quitRequestId" to ControlValue.Text(publicRequestId),
            "pid" to ControlValue.IntegerValue(pid),
            "startedAtEpochMillis" to ControlValue.IntegerValue(started),
        )), controllerId = controllerId), clientTimeoutSeconds = 3)
}
