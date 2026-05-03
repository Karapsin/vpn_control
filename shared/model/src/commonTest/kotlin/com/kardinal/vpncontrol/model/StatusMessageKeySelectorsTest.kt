package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class StatusMessageKeySelectorsTest {
    @Test
    fun subscriptionRefreshStartSelectsManualAndAutoVariants() {
        assertEquals(StatusMessageKey.REFRESHING_SUBSCRIPTION, SubscriptionStatusMessageKeys.refreshStart(1, auto = false))
        assertEquals(StatusMessageKey.REFRESHING_SUBSCRIPTIONS, SubscriptionStatusMessageKeys.refreshStart(2, auto = false))
        assertEquals(StatusMessageKey.AUTO_REFRESHING_SUBSCRIPTION, SubscriptionStatusMessageKeys.refreshStart(1, auto = true))
        assertEquals(StatusMessageKey.AUTO_REFRESHING_SUBSCRIPTIONS, SubscriptionStatusMessageKeys.refreshStart(2, auto = true))
    }

    @Test
    fun backgroundRefreshReplacementFailureSelectsMostSpecificVariant() {
        assertEquals(
            StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED,
            BackgroundRefreshStatusMessageKeys.replacementFailed(
                failedLabel = null,
                selectedSourceFailed = false,
                rollbackMessage = "",
            ),
        )
        assertEquals(
            StatusMessageKey.BACKGROUND_REFRESH_REPLACEMENT_FAILED_WITH_FAILURES_SOURCE_FAILED_ROLLBACK,
            BackgroundRefreshStatusMessageKeys.replacementFailed(
                failedLabel = "Example",
                selectedSourceFailed = true,
                rollbackMessage = "Rollback failed",
            ),
        )
    }

    @Test
    fun backgroundRefreshKeptCurrentSelectsPartialPreviousCacheVariant() {
        assertEquals(
            StatusMessageKey.BACKGROUND_REFRESH_KEPT_CURRENT_PARTIAL_PREVIOUS_CACHE,
            BackgroundRefreshStatusMessageKeys.keptCurrent(
                failedLabel = "Example",
                selectedSourceFailed = true,
            ),
        )
    }
}
