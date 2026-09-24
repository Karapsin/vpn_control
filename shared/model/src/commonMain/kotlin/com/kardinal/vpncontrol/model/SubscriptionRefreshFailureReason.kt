package com.kardinal.vpncontrol.model

/** Safe, cross-platform reasons exposed for a failed subscription refresh. */
enum class SubscriptionRefreshFailureReason {
    TLS,
    CONNECTIVITY,
    PARSE,
    PREPARATION,
    PERSISTENCE,
    OTHER;

    val wireName: String get() = name
}

/** Carries a safe reason while retaining a native cause for platform-local classification only. */
class SubscriptionRefreshFailureException(
    val reason: SubscriptionRefreshFailureReason,
    cause: Throwable? = null,
) : Exception(null, cause)
