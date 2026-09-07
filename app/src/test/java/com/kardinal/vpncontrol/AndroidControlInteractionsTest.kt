package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidControlInteractionsTest {
    @Test fun grantedSearchRetainsOnlyItsOriginalActivityUntilOwnerCleanup() = runTest {
        var now = 0L
        val registry = AndroidControlInteractions("owner", { now }, 100)
        val token = registry.create("search", ControlOperationId.FIND_BEST)
        assertFalse(registry.retainGrantedSearch(token))
        val session = requireNotNull(registry.attach(token, "owner", null))
        registry.resolve(token, session, ControlCode.OK)
        assertTrue(registry.retainGrantedSearch(token))
        now = 101
        assertTrue(registry.isActive(token))
        assertNull(registry.tokenFor("search"))
        assertNull(registry.attach(token, "owner", null))
        assertNull(registry.attach(token, "owner", "foreign"))
        assertNull(registry.attach(token, "replacement", session))
        assertEquals(session, registry.attach(token, "owner", session))
        assertNull(registry.action(token, session))
        assertFalse(registry.claimConsent(token, session))
        registry.cancel("search")
        assertTrue(registry.isActive(token))
        assertEquals(ControlCode.OK, registry.await(token))
        registry.finish(token)
        assertFalse(registry.isActive(token))
        assertNull(registry.attach(token, "owner", session))
    }

    @Test fun denialAndOtherActionCannotPinConsumedConsentCapabilities() = runTest {
        val registry = AndroidControlInteractions("owner")
        for ((action, answer) in listOf(ControlOperationId.FIND_BEST to ControlCode.PERMISSION_DENIED,
            ControlOperationId.ON to ControlCode.OK)) {
            val token = registry.create(action.wireName, action)
            val session = requireNotNull(registry.attach(token, "owner", null))
            registry.resolve(token, session, answer)
            assertFalse(registry.retainGrantedSearch(token))
            assertNull(registry.attach(token, "owner", session))
            registry.finish(token)
        }
    }

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
