package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidControlInteractionsTest {
    @Test fun tokensBindOwnerActionAndOneRecreatableSession() = runTest {
        val registry = AndroidControlInteractions("owner")
        val token = registry.create("operation", ControlOperationId.RESTART)
        assertNull(registry.attach(token, "replacement-owner", null))
        val session = requireNotNull(registry.attach(token, "owner", null))
        assertNull(registry.attach(token, "owner", null))
        assertEquals(session, registry.attach(token, "owner", session))
        assertTrue(registry.claimConsent(token, session))
        assertFalse(registry.claimConsent(token, session))
        registry.resolve(token, "wrong-session", ControlCode.OK)
        assertEquals(token, registry.tokenFor("operation"))
        registry.resolve(token, session, ControlCode.PERMISSION_DENIED)
        assertEquals(ControlCode.PERMISSION_DENIED, registry.await(token))
        registry.finish(token)
        assertNull(registry.attach(token, "owner", session))
    }

    @Test fun expiryAndProcessReplacementNeverAuthorizeConsentOrStart() = runTest {
        var now = 0L
        val registry = AndroidControlInteractions("owner", { now }, 100)
        val token = registry.create("operation", ControlOperationId.ON)
        now = 101
        assertNull(registry.attach(token, "owner", null))
        assertEquals(ControlCode.INTERACTION_REQUIRED, registry.await(token))
        assertNull(AndroidControlInteractions("replacement").attach(token, "owner", null))
        assertTrue(runCatching { registry.create("off", ControlOperationId.OFF) }.isFailure)
    }
}
