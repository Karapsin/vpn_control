package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlin.test.*

class DesktopMacAuthorizationReplyTest {
    private val job = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
    private fun reply(error: Int, identity: String = job) =
        "VPN_CONTROL_AUTH_V1\n$identity\n$error\n".encodeToByteArray()

    @Test fun authorizationWaitUsesNoStartProofOnlyWhenProtectedReceiptIsAbsent() = kotlinx.coroutines.runBlocking {
        var checks = 0
        fun prepared(read: () -> DesktopInstallJobReceipt) = DesktopReceiptPreparedInstall(job,
            readReceipt = read, publishCommit = { error("No commit") },
            requestCancellation = { error("No cancellation") }, release = {}, timeoutMillis = 0,
            authorizationFailure = { checks++; IllegalStateException(ControlCode.INTERACTION_REQUIRED.name) })
        assertEquals("INTERACTION_REQUIRED", prepared { throw java.nio.file.NoSuchFileException(job) }
            .awaitAuthorization().exceptionOrNull()?.message)
        assertEquals(1, checks)
        assertTrue(prepared { DesktopInstallJobReceipt(job, 2, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK) }
            .awaitAuthorization().isSuccess)
        val inaccessible = java.nio.file.AccessDeniedException(job)
        assertSame(inaccessible, prepared { throw inaccessible }.awaitAuthorization().exceptionOrNull())
        assertEquals(1, checks)
    }

    @Test fun nativeAuthorizationErrorsHaveDistinctCorrelatedOutcomes() {
        assertEquals(ControlCode.CANCELLED, DesktopMacAuthorizationReply.notStartedCode(job, 0, reply(-128)))
        assertEquals(ControlCode.CANCELLED, DesktopMacAuthorizationReply.notStartedCode(job, 0, reply(-60006)))
        assertEquals(ControlCode.PERMISSION_DENIED, DesktopMacAuthorizationReply.notStartedCode(job, 0, reply(-60005)))
        assertEquals(ControlCode.INTERACTION_REQUIRED, DesktopMacAuthorizationReply.notStartedCode(job, 0, reply(-60007)))
    }

    @Test fun processExitOrUncorrelatedOutputCannotProveNoWorkerStarted() {
        for (bytes in listOf(byteArrayOf(), reply(1), reply(0), reply(-1), reply(-128, "foreign"),
            reply(-128) + byteArrayOf(10), "User canceled. (-128)".encodeToByteArray(), ByteArray(257))) {
            assertNull(DesktopMacAuthorizationReply.notStartedCode(job, 0, bytes))
        }
        assertNull(DesktopMacAuthorizationReply.notStartedCode(job, 1, reply(-128)))
    }
}
