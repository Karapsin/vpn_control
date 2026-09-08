package com.kardinal.vpncontrol.desktop

import com.sun.jna.platform.win32.WinNT
import java.nio.file.Path
import kotlin.test.*

class DesktopWindowsVpnHelperChannelTest {
    @Test fun admissionRemainsOwnedAcrossReadinessAndCommitUntilVerifiedNativeDisposal() {
        val native = Channel()
        val lease = Lease()
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        assertEquals(77, channel.childPid)
        channel.commit()
        assertEquals(1, native.commits)
        assertTrue(channel.status().running)
        assertEquals(0, lease.closes)
        native.exited = true
        channel.close()
        assertTrue(native.closed)
        assertEquals(1, lease.closes)
        channel.close()
        assertEquals(1, native.closes)
        assertEquals(1, lease.closes)
    }

    @Test fun unknownExitOrNativeCloseFailureNeverReleasesAdmission() {
        val native = Channel()
        val lease = Lease()
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        assertFails { channel.close() }
        assertEquals(0, lease.closes)
        assertFalse(channel.childExited())
        native.exited = true
        native.closeFailures = 1
        assertFails { channel.close() }
        assertEquals(0, lease.closes)
        assertFalse(native.closed)
        channel.close()
        assertEquals(1, lease.closes)
    }

    @Test fun admissionCloseRetryNeverReusesAClosedNativeProcessHandle() {
        val native = Channel().apply { exited = true }
        val lease = Lease().apply { closeFailures = 1 }
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        assertFailsWith<WindowsInstallNativeFailure> { channel.close() }
        assertTrue(native.closed)
        assertTrue(channel.childExited())
        assertTrue(channel.abort())
        assertFalse(channel.status().running)
        channel.stop(true)
        assertFails { channel.commit() }
        channel.close()
        assertEquals(1, native.closes)
        assertEquals(2, lease.closes)
    }

    @Test fun unknownPreparedAbortPreservesTheCandidateAndItsAdmissionForRecovery() {
        val native = Channel()
        val lease = Lease()
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        val prepared = DesktopPreparedWindowsRuntimeProcess(channel, Path.of("unused-component-log"))
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.close() }
        assertEquals("OUTCOME_UNKNOWN", failure.code)
        val retained = assertNotNull(failure.unresolvedRuntime)
        assertTrue(retained.isAlive)
        assertEquals(0, native.commits)
        assertEquals(0, lease.closes)
        native.exited = true
        assertFalse(retained.isAlive)
        retained.close()
        assertEquals(1, lease.closes)
    }

    @Test fun failedLeaseCloseAfterPreparedAbortKeepsAnExitedRecoverableOwner() {
        val native = Channel().apply { exited = true }
        val lease = Lease().apply { closeFailures = 1 }
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        val prepared = DesktopPreparedWindowsRuntimeProcess(channel, Path.of("unused-component-log"))
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.close() }
        val retained = assertNotNull(failure.unresolvedRuntime)
        assertFalse(retained.isAlive, "Read-only admission cleanup must not invent a live runtime")
        retained.close()
        assertEquals(1, native.closes)
        assertEquals(2, lease.closes)
    }

    @Test fun candidateAllocationFailureCannotAuthorizeOrLoseTheUnstartedHelperLease() {
        val native = Channel().apply { exited = true }
        val lease = Lease()
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        var launches = 0
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            desktopWindowsPrepareFixedHelper(channel, Path.of("unused-component-log"),
                stage = { DesktopWindowsRuntimePreparationStage.AUTHORIZATION },
                authorizeAndPrepare = { launches++ },
                allocateCandidate = { throw OutOfMemoryError("injected before external authorization") })
        }
        assertEquals(0, launches, "External helper authorization preceded candidate ownership allocation")
        assertEquals("RESOURCE_EXHAUSTED", failure.code)
        assertNull(failure.unresolvedRuntime)
        assertNull(failure.retainedAdmission)
        assertEquals(1, native.closes)
        assertEquals(1, lease.closes)
    }

    @Test fun allocationFailureWithCloseFailureKeepsOnlyUnstartedAdmissionOwnership() {
        val native = Channel().apply { exited = true }
        val lease = Lease().apply { closeFailures = 1 }
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        var launches = 0
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            desktopWindowsPrepareFixedHelper(channel, Path.of("unused-component-log"),
                stage = { DesktopWindowsRuntimePreparationStage.AUTHORIZATION },
                authorizeAndPrepare = { launches++ },
                allocateCandidate = { throw OutOfMemoryError("injected") })
        }
        assertEquals(0, launches)
        assertEquals("RESOURCE_EXHAUSTED", failure.code)
        assertNull(failure.unresolvedRuntime)
        assertSame(channel, failure.retainedAdmission)
        assertTrue(native.closed)
        failure.retainedAdmission!!.close()
        assertEquals(1, native.closes)
        assertEquals(2, lease.closes)
    }

    @Test fun failureAfterAuthorizationPreservesUnknownNativeOwnershipAndLease() {
        val native = Channel()
        val lease = Lease()
        val channel = DesktopWindowsVpnHelperChannel(native, lease)
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            desktopWindowsPrepareFixedHelper(channel, Path.of("unused-component-log"),
                stage = { DesktopWindowsRuntimePreparationStage.HELPER_CONNECTION },
                authorizeAndPrepare = { throw OutOfMemoryError("after authorization") })
        }
        assertEquals("OUTCOME_UNKNOWN", failure.code)
        val retained = assertNotNull(failure.unresolvedRuntime)
        assertTrue(retained.isAlive)
        assertEquals(0, lease.closes)
        native.exited = true
        assertFalse(retained.isAlive)
        retained.close()
        assertEquals(1, lease.closes)
    }

    @Test fun anAuthorizationReplyFailureStillTransfersTheCapturedNativeHandle() {
        val process = WinNT.HANDLE(com.sun.jna.Pointer.createConstant(71))
        var captured: WinNT.HANDLE? = null
        var retained: WinNT.HANDLE? = null
        val original = OutOfMemoryError("after native handle publication")
        val failure = assertFailsWith<OutOfMemoryError> {
            desktopWindowsRetainAuthorizedHelper(
                authorize = { captured = process; throw original },
                capturedProcess = { captured }, retain = { retained = it })
        }
        assertSame(original, failure)
        assertSame(process, retained, "Published ShellExecute handle was lost when its reply threw")
    }

    @Test fun bothAcceptedAndRejectedRepliesRetainOnlyTheirActualCapturedHandle() {
        val process = WinNT.HANDLE(com.sun.jna.Pointer.createConstant(72))
        for (accepted in listOf(false, true)) for (captured in listOf(null, process)) {
            var retained: WinNT.HANDLE? = null
            assertEquals(accepted, desktopWindowsRetainAuthorizedHelper(
                authorize = { accepted }, capturedProcess = { captured }, retain = { retained = it }))
            assertSame(captured, retained)
        }
    }

    private class Channel : DesktopWindowsPreparedRuntimeChannel {
        override val childPid = 77L
        var exited = false
        var closed = false
        var closeFailures = 0
        var commits = 0
        var closes = 0
        private fun retained() { check(!closed) { "Queried an already closed process handle" } }
        override fun commit() { retained(); commits++ }
        override fun abort(): Boolean { retained(); return exited }
        override fun childExited(): Boolean { retained(); return exited }
        override fun status(): DesktopWindowsRuntimeStatus { retained(); return DesktopWindowsRuntimeStatus(!exited) }
        override fun stop(force: Boolean) { retained() }
        override fun close() {
            retained(); closes++
            check(exited) { "OUTCOME_UNKNOWN" }
            if (closeFailures-- > 0) throw WindowsInstallNativeFailure(32)
            closed = true
        }
    }

    private class Lease : DesktopWindowsVpnHelperLease {
        override val executable = "C:\\Apps\\VPN\\app\\native\\windows-amd64\\vpn-control-vpn-broker.exe"
        override val owner = DesktopWindowsRuntimeResourceNativeOwner(123, 456, "S-1-5-21-1-2-3-1001")
        var closes = 0
        var closeFailures = 0
        override fun parameters(pipeName: String): String = error("No process is launched by this fixture")
        override fun verifyStartedProcess(process: WinNT.HANDLE) = error("No native process exists in this fixture")
        override fun close() {
            closes++
            if (closeFailures-- > 0) throw WindowsInstallNativeFailure(32)
        }
    }
}
