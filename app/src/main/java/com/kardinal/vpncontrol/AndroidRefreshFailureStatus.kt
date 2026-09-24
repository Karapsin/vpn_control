package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionRefreshFailureReason
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionStatusMessages

/** One typed status path for persisted and GUI subscription-refresh failures. */
internal fun androidRefreshFailureStatus(
    subscriptions: List<SubscriptionSource>,
    source: SubscriptionSource,
    reason: SubscriptionRefreshFailureReason,
): String = SubscriptionStatusMessages.refreshFailure(
    reason,
    SubscriptionSourceLogic.safeSourceLabelFor(subscriptions, source.url),
)
