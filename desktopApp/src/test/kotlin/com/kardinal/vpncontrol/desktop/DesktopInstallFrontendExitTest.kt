package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopInstallFrontendExitTest {
    private val identity = DesktopFrontendProcessIdentity("00000000-0000-0000-0000-000000000001", 123, 456)
    private val correlation = DesktopInstallCorrelation("00000000-0000-0000-0000-000000000002",
        "00000000-0000-0000-0000-000000000003", "00000000-0000-0000-0000-000000000004")
    private val job = "00000000-0000-0000-0000-000000000005"
    private fun acknowledged(command: DesktopCliCommand.ControlSubmit) = DesktopCliResponse.success(
        ControlProtocolCodec.encodeResult(ControlResult(command.request.controllerId, command.request.requestId,
            ControlCode.OK, 0, data = command.request.command.arguments)))

    @Test fun acknowledgementDoesNotReleaseAnAliveFrontendAndRetriesKeepTheirIdentity() = runBlocking {
        val requests = mutableListOf<DesktopCliCommand.ControlSubmit>()
        var pauses = 0
        DesktopInstallFrontendExit(identity, correlation, job,
            request = { requests += it; acknowledged(it) },
            observe = { if (pauses < 2) DesktopFrontendProcessObservation.SAME else DesktopFrontendProcessObservation.GONE },
            pause = { pauses++ }).awaitExit()
        assertEquals(2, requests.size)
        assertEquals(requests[0], requests[1])
        assertEquals(identity.registrationId, requests[0].request.controllerId)
        assertEquals(ControlValue.IntegerValue(identity.pid), requests[0].request.command.arguments["pid"])
    }

    @Test fun unknownProcessMetadataKeepsOwnerAndDoesNotAddressAnUnprovenProcess() = runBlocking {
        var pauses = 0
        var requests = 0
        DesktopInstallFrontendExit(identity, correlation, job,
            request = { requests++; acknowledged(it) },
            observe = { when (pauses) {
                0 -> DesktopFrontendProcessObservation.UNKNOWN
                1 -> DesktopFrontendProcessObservation.SAME
                else -> DesktopFrontendProcessObservation.GONE
            } }, pause = { pauses++ }).awaitExit()
        assertEquals(2, pauses)
        assertEquals(1, requests)
    }

    @Test fun lostResponseRetriesTheSameFrontendRequestWithoutReplayingInstallation() = runBlocking {
        val requests = mutableListOf<DesktopCliCommand.ControlSubmit>()
        DesktopInstallFrontendExit(identity, correlation, job,
            request = { requests += it; throw java.io.IOException("lost response") },
            observe = { if (requests.size < 2) DesktopFrontendProcessObservation.SAME else DesktopFrontendProcessObservation.GONE },
            pause = {}).awaitExit()
        assertEquals(2, requests.size)
        assertEquals(requests.first(), requests.last())
        assertTrue(requests.all { it.request.command.operation == ControlOperationId.QUIT })
    }

    @Test fun cancellationStopsTheObserverWithoutClaimingProcessExit() = runBlocking {
        var paused = false
        assertFailsWith<CancellationException> {
            DesktopInstallFrontendExit(identity, correlation, job,
                request = { throw CancellationException("owner closed") },
                observe = { DesktopFrontendProcessObservation.SAME }, pause = { paused = true }).awaitExit()
        }
        assertFalse(paused)
    }

    @Test fun currentProcessAndKnownDifferentGenerationAreDistinguished() {
        val current = DesktopFrontendProcessIdentity.current(identity.registrationId)
        assertEquals(DesktopFrontendProcessObservation.SAME, desktopFrontendProcessObservation(current))
        // The live PID belongs to a different, positively identified generation;
        // no request or signal is sent to that replacement process.
        assertEquals(DesktopFrontendProcessObservation.GONE,
            desktopFrontendProcessObservation(current.copy(startedAtEpochMillis = current.startedAtEpochMillis - 1)))
    }
}
