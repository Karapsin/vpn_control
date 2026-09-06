package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DesktopControlLocationIdentityTest {
    @Test
    fun opaqueIdentityIsStableOnlyWithinOwnerAndDoesNotExposeInput() {
        val identities = DesktopControlLocationIdentity()
        val id = identities.id("private-source", "private-profile")
        assertEquals(id, identities.id("private-source", "private-profile"))
        assertNotEquals(id, DesktopControlLocationIdentity().id("private-source", "private-profile"))
        assertNotEquals(identities.id("ab", "c"), identities.id("a", "bc"))
        assertEquals(null, identities.id("source", ""))
        assertTrue(requireNotNull(id).matches(Regex("[0-9a-f]{64}")))
    }
}
