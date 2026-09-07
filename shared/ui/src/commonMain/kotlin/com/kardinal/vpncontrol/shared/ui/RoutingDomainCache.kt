package com.kardinal.vpncontrol.shared.ui

internal fun routingDomainCacheKey(domains: List<String>?): Any = RoutingDomainIdentity(domains)

/** Compose keys must release an equal-but-replaced large immutable backing store. */
private class RoutingDomainIdentity(private val domains: List<String>?) {
    override fun equals(other: Any?) = other is RoutingDomainIdentity && domains === other.domains
    // Compose compares the small key set directly; never hash all domain contents.
    override fun hashCode() = 0
}

/** Referential equality also prevents mutableStateOf from retaining an equal old Pair. */
internal class RoutingDomainOrder(val domains: List<String>, val indices: List<Int>)
