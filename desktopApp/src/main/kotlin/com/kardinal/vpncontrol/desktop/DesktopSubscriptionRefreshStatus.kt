package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionSource

internal object DesktopSubscriptionRefreshStatus {
    fun noSubscriptionsToRefresh(): IllegalStateException =
        IllegalStateException(StatusMessages.noSubscriptionsToRefresh())

    fun progress(subscription: SubscriptionSource): String =
        StatusMessages.refreshingSubscriptionNamed(subscriptionDisplayName(subscription))

    fun successfulLocationRefresh(locationCount: Int): String =
        StatusMessages.locationsRefreshed(locationCount)

    fun failedSubscriptionRefresh(subscription: SubscriptionSource, error: Throwable): String =
        error.message ?: StatusMessages.failedToRefresh(subscriptionDisplayName(subscription))

    fun summary(
        refreshedCount: Int,
        failedSubscriptionNames: List<String>,
        totalCount: Int,
    ): String = SubscriptionRefreshResultLogic.genericSummary(
        refreshedCount = refreshedCount,
        failedSubscriptionNames = failedSubscriptionNames,
        totalCount = totalCount,
    )
}
