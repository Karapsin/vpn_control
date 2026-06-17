package com.kardinal.vpncontrol.data

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class RemoteSourceSupportTest {
    @Test
    fun redactRemoteSourceUrlRemovesPathQueryAndFragmentTokens() {
        val redacted = redactRemoteSourceUrl(
            "https://user:secret@example.com/subscription/11111111-1111-4111-8111-111111111111?token=secret#frag",
        )

        assertEquals("https://example.com/<redacted>", redacted)
        assertFalse(redacted.contains("subscription"))
        assertFalse(redacted.contains("11111111-1111-4111-8111-111111111111"))
        assertFalse(redacted.contains("secret"))
        assertFalse(redacted.contains("token"))
        assertFalse(redacted.contains("frag"))
    }
}
