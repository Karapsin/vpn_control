package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertTrue

class DesktopSubscriptionSourceValidationTest {
    @Test
    fun acceptsHttpsSubscriptionSource() {
        val result = DesktopSubscriptionSourceValidation.validate("https://example.com/sub.txt")

        assertTrue(result.isSuccess)
    }

    @Test
    fun rejectsInsecureHttpSubscriptionSourceWithSpecificMessage() {
        val result = DesktopSubscriptionSourceValidation.validate("http://example.com/sub.txt")

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()?.message.orEmpty().contains("Use https:// instead"))
    }

    @Test
    fun rejectsBlankOrUnsupportedSourcesWithGenericHttpsHint() {
        val blank = DesktopSubscriptionSourceValidation.validate(" ")
        val unsupported = DesktopSubscriptionSourceValidation.validate("ftp://example.com/sub.txt")

        assertTrue(blank.isFailure)
        assertTrue(unsupported.isFailure)
        assertTrue(blank.exceptionOrNull()?.message.orEmpty().contains("valid https:// subscription URL"))
        assertTrue(unsupported.exceptionOrNull()?.message.orEmpty().contains("valid https:// subscription URL"))
    }
}
