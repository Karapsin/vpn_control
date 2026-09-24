package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshFailureException
import com.kardinal.vpncontrol.model.SubscriptionRefreshFailureReason
import com.kardinal.vpncontrol.SubscriptionRefreshResultLogic
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.cert.CertificateException
import java.util.Collections
import java.util.IdentityHashMap
import javax.net.ssl.SSLException

internal object DesktopSubscriptionRefreshStatus {
    fun noSubscriptionsToRefresh(): IllegalStateException =
        IllegalStateException(SubscriptionStatusMessages.noSubscriptionsToRefresh())

    fun progress(subscription: SubscriptionSource): String =
        SubscriptionStatusMessages.refreshingSubscriptionNamed(subscriptionDisplayName(subscription))

    fun successfulLocationRefresh(locationCount: Int): String =
        SubscriptionStatusMessages.locationsRefreshed(locationCount)

    fun failedSubscriptionRefresh(subscription: SubscriptionSource, reason: SubscriptionRefreshFailureReason): String =
        SubscriptionStatusMessages.refreshFailure(reason, subscriptionDisplayName(subscription))

    fun failureReason(error: Throwable): SubscriptionRefreshFailureReason {
        val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
        val chain = mutableListOf<Throwable>()
        var current: Throwable? = error
        while (current != null && chain.size < 16 && seen.add(current)) {
            chain += current
            current = current.cause
        }
        val explicit = chain.filterIsInstance<SubscriptionRefreshFailureException>().firstOrNull()
        return when {
            explicit != null -> explicit.reason
            chain.any { it is SSLException || it is CertificateException } -> SubscriptionRefreshFailureReason.TLS
            chain.any { it is ConnectException || it is UnknownHostException || it is SocketTimeoutException || it is IOException } ->
                SubscriptionRefreshFailureReason.CONNECTIVITY
            else -> SubscriptionRefreshFailureReason.OTHER
        }
    }

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
