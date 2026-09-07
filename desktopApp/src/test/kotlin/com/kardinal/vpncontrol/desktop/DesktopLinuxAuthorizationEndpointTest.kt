package com.kardinal.vpncontrol.desktop

import kotlinx.serialization.json.Json
import kotlin.test.*

class DesktopLinuxAuthorizationEndpointTest {
    private val owner = DesktopLinuxAuthorizationOwner(123, 456, 1000)
    private val endpoint = DesktopControlEndpoint(1234, "controller", "secret", linuxAuthorizationOwner = owner)

    @Test fun optionalTupleRoundTripsNativeTicksWithoutEpochConversion() {
        assertNull(decodeLinuxAuthorizationOwner(null))
        assertEquals(owner, decodeLinuxAuthorizationOwner(encodeLinuxAuthorizationOwner(owner)))
        assertFalse(endpoint.toString().contains("secret"))
    }

    @Test fun partialUnknownStringAndNonIntegralFieldsFailClosed() {
        for (json in listOf("null", "[]", "{}", "{\"pid\":123,\"uid\":1000}",
            "{\"pid\":123,\"startTicks\":456,\"uid\":1000,\"extra\":1}",
            "{\"pid\":\"123\",\"startTicks\":456,\"uid\":1000}",
            "{\"pid\":123,\"startTicks\":456.0,\"uid\":1000}",
            "{\"pid\":123,\"startTicks\":4e2,\"uid\":1000}",
            "{\"pid\":123,\"startTicks\":456,\"uid\":0}",
            "{\"pid\":2147483648,\"startTicks\":456,\"uid\":1000}",
            "{\"pid\":123,\"startTicks\":9223372036854775808,\"uid\":1000}")) {
            assertFails(json) { decodeLinuxAuthorizationOwner(Json.parseToJsonElement(json)) }
        }
    }

    @Test fun controllerPinPrecedesNativeVerificationAndLegacyNeedsInteraction() {
        var checks = 0
        val conflict = assertFails { verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(endpoint, "replacement") { checks++; true } }
        assertEquals("CONFLICT", conflict.message)
        assertEquals(0, checks)
        val legacy = DesktopControlEndpoint(1234, "controller", "secret")
        assertEquals("INTERACTION_REQUIRED", assertFails {
            verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(legacy, "controller") { checks++; true }
        }.message)
        assertEquals(0, checks)
    }

    @Test fun mismatchedNativeOwnerFailsAndExactVerifiedTupleIsReturned() {
        assertEquals("CONFLICT", assertFails {
            verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(endpoint, "controller") { false }
        }.message)
        assertEquals(owner, verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(endpoint, "controller") {
            assertEquals(owner, it); true
        })
    }
}
