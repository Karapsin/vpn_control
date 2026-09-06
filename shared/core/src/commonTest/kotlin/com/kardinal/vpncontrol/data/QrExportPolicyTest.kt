package com.kardinal.vpncontrol.data

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QrExportPolicyTest {
    @Test fun limitCountsUtf8BytesRatherThanCharacters() {
        for (payload in listOf("a".repeat(1600), "é".repeat(800), "😀".repeat(400))) {
            assertEquals(1600, QrExportPolicy.byteCount(payload))
            assertTrue(QrExportPolicy.validate(payload).isSuccess)
            assertFalse(QrExportPolicy.fits(payload + "a"))
            assertEquals("QR_TOO_LARGE", QrExportPolicy.validate(payload + "a").exceptionOrNull()?.message)
        }
    }

    @Test fun emptyOrMalformedPayloadIsNotExported() {
        assertTrue(QrExportPolicy.validate("").isFailure)
        assertTrue(QrExportPolicy.validate("\uD800").isFailure)
    }
}
