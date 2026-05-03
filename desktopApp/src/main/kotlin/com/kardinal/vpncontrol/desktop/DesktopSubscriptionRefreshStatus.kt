package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.SubscriptionSource

internal object DesktopSubscriptionRefreshStatus {
    fun noSubscriptionsToRefresh(): IllegalStateException =
        IllegalStateException(SubscriptionStatusMessages.noSubscriptionsToRefresh())

    fun progress(subscription: SubscriptionSource): String =
        SubscriptionStatusMessages.refreshingSubscriptionNamed(subscriptionDisplayName(subscription))

    fun successfulLocationRefresh(locationCount: Int): String =
        SubscriptionStatusMessages.locationsRefreshed(locationCount)

    fun failedSubscriptionRefresh(subscription: SubscriptionSource, error: Throwable): String =
        error.message ?: SubscriptionStatusMessages.failedToRefresh(subscriptionDisplayName(subscription))

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
