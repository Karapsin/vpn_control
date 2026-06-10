package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class BenchmarkValidationSettingsTest {
    @Test
    fun subscriptionRefreshConcurrencyIsClamped() {
        assertEquals(
            BenchmarkValidationSettings.MIN_SUBSCRIPTION_REFRESH_CONCURRENCY,
            BenchmarkValidationSettings(subscriptionRefreshConcurrency = 0)
                .normalized()
                .subscriptionRefreshConcurrency,
        )
        assertEquals(
            BenchmarkValidationSettings.MAX_SUBSCRIPTION_REFRESH_CONCURRENCY,
            BenchmarkValidationSettings(subscriptionRefreshConcurrency = 99)
                .normalized()
                .subscriptionRefreshConcurrency,
        )
    }

    @Test
    fun activeVerificationWindowSizeIsClamped() {
        assertEquals(
            BenchmarkValidationSettings.MIN_ACTIVE_VERIFICATION_WINDOW_SIZE,
            BenchmarkValidationSettings(activeVerificationWindowSize = 0)
                .normalized()
                .activeVerificationWindowSize,
        )
        assertEquals(
            BenchmarkValidationSettings.MAX_ACTIVE_VERIFICATION_WINDOW_SIZE,
            BenchmarkValidationSettings(activeVerificationWindowSize = 99)
                .normalized()
                .activeVerificationWindowSize,
        )
    }
}
