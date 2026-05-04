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
}
