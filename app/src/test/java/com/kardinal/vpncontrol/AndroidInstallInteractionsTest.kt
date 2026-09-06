package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidInstallInteractionsTest {
    @Test fun permissionReturnIsRecheckedAndLockedOrUnfocusedNeverDispatches() {
        assertEquals(AndroidInstallStage.WAIT, androidInstallStage(false, true, true))
        assertEquals(AndroidInstallStage.WAIT, androidInstallStage(false, false, false))
        assertEquals(AndroidInstallStage.REQUEST_PERMISSION, androidInstallStage(true, false, false))
        assertEquals(AndroidInstallStage.DENIED, androidInstallStage(true, false, true))
        assertEquals(AndroidInstallStage.DISPATCH, androidInstallStage(true, true, true))
        assertEquals(AndroidInstallStage.DISPATCH, androidInstallStage(true, true, false))
    }
    @Test fun installStagesAreOwnerBoundOneShotAndCancellationPreventsDispatch() = runTest {
        val registry = AndroidControlInteractions("owner")
        val token = registry.create("operation", ControlOperationId.UPDATES_INSTALL)
        assertNull(registry.attach(token, "other", null))
        val session = requireNotNull(registry.attach(token, "owner", null))
        assertEquals(ControlOperationId.UPDATES_INSTALL, registry.action(token, session))
        assertTrue(registry.claimConsent(token, session))
        assertFalse(registry.claimConsent(token, session))
        registry.cancel("operation")
        var dispatched = false
        assertFalse(registry.dispatchInstall(token, session) { dispatched = true })
        assertFalse(dispatched)
        assertEquals(ControlCode.CANCELLED, registry.await(token))
    }

    @Test fun recreatedSessionCanDispatchOnceAndFailedLaunchNeverReportsSuccess() = runTest {
        val registry = AndroidControlInteractions("owner")
        val token = registry.create("operation", ControlOperationId.UPDATES_INSTALL)
        val session = requireNotNull(registry.attach(token, "owner", null))
        assertEquals(session, registry.attach(token, "owner", session))
        assertFalse(registry.dispatchInstall(token, session) { error("launch rejected") })
        assertEquals(ControlCode.RUNTIME_FAILED, registry.await(token))
        assertFalse(registry.dispatchInstall(token, session) { fail("must not retry") })
    }

    @Test fun expiredInstallAndPermissionOnlyResolutionCannotReportHandoff() = runTest {
        var now = 0L
        val registry = AndroidControlInteractions("owner", clock = { now }, retentionMillis = 10)
        val token = registry.create("operation", ControlOperationId.UPDATES_INSTALL)
        val session = requireNotNull(registry.attach(token, "owner", null))
        registry.resolve(token, session, ControlCode.OK)
        assertNotNull(registry.tokenFor("operation"))
        now = 11
        assertFalse(registry.dispatchInstall(token, session) { fail("expired") })
        assertEquals(ControlCode.INTERACTION_REQUIRED, registry.await(token))
    }
}
