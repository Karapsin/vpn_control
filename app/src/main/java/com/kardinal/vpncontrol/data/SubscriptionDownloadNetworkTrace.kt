package com.kardinal.vpncontrol.data

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Protocol

/**
 * Retains only bounded network categories for one subscription call. It is rendered on failure;
 * addresses, hostnames, ports, and exception messages never enter the diagnostic output.
 */
internal class SubscriptionDownloadNetworkTrace : EventListener() {
    private val dnsCounts = linkedMapOf<String, Int>()
    private val connections = mutableListOf<ConnectionAttempt>()
    private var omittedConnections = 0
    private var currentConnection: ConnectionAttempt? = null

    override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) {
        synchronized(this) {
            inetAddressList.forEach { address ->
                val key = "${addressFamily(address)}-${addressScope(address)}"
                dnsCounts[key] = (dnsCounts[key] ?: 0) + 1
            }
        }
    }

    override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
        synchronized(this) {
            val attempt = connectionAttempt(inetSocketAddress, proxy, "started")
            currentConnection = if (connections.size < MAX_CONNECTION_ATTEMPTS) {
                connections += attempt
                attempt
            } else {
                omittedConnections++
                null
            }
        }
    }

    override fun connectEnd(
        call: Call,
        inetSocketAddress: InetSocketAddress,
        proxy: Proxy,
        protocol: Protocol?,
    ) = updateLatestConnection(inetSocketAddress, proxy, "completed")

    override fun connectFailed(
        call: Call,
        inetSocketAddress: InetSocketAddress,
        proxy: Proxy,
        protocol: Protocol?,
        ioe: java.io.IOException,
    ) = updateLatestConnection(inetSocketAddress, proxy, "failed")

    fun summary(): String = synchronized(this) {
        val dns = DNS_CATEGORY_ORDER.mapNotNull { category ->
            dnsCounts[category]?.let { "$category:$it" }
        }.joinToString(",").ifBlank { "none" }
        val connection = connections.joinToString(",") { attempt ->
            "${attempt.proxy}-${attempt.family}-${attempt.scope}-${attempt.outcome}"
        }.ifBlank { "none" }
        buildString {
            append("dns=").append(dns)
            append(" connect=").append(connection)
            if (omittedConnections > 0) append(" connect_omitted=").append(omittedConnections)
        }
    }

    private fun updateLatestConnection(address: InetSocketAddress, proxy: Proxy, outcome: String) {
        synchronized(this) {
            val expected = connectionAttempt(address, proxy, "")
            currentConnection?.takeIf {
                it.proxy == expected.proxy && it.family == expected.family && it.scope == expected.scope && it.outcome == "started"
            }?.outcome = outcome
            currentConnection = null
        }
    }

    private fun connectionAttempt(address: InetSocketAddress, proxy: Proxy, outcome: String): ConnectionAttempt {
        val resolved = address.address
        return ConnectionAttempt(
            proxy = when (proxy.type()) {
                Proxy.Type.DIRECT -> "direct"
                Proxy.Type.HTTP -> "http"
                Proxy.Type.SOCKS -> "socks"
            },
            family = resolved?.let(::addressFamily) ?: "unresolved",
            scope = resolved?.let(::addressScope) ?: "unresolved",
            outcome = outcome,
        )
    }

    private fun addressFamily(address: InetAddress): String = when (address) {
        is Inet4Address -> "v4"
        is Inet6Address -> "v6"
        else -> "unknown"
    }

    private fun addressScope(address: InetAddress): String = when {
        address.isLoopbackAddress -> "loopback"
        address.isLinkLocalAddress -> "linklocal"
        address.isSiteLocalAddress || isIpv6UniqueLocal(address) -> "private"
        address.isAnyLocalAddress || address.isMulticastAddress -> "unknown"
        else -> "public"
    }

    private fun isIpv6UniqueLocal(address: InetAddress): Boolean = address is Inet6Address &&
        (address.address.firstOrNull()?.toInt()?.and(0xfe) == 0xfc)

    private data class ConnectionAttempt(
        val proxy: String,
        val family: String,
        val scope: String,
        var outcome: String,
    )

    private companion object {
        const val MAX_CONNECTION_ATTEMPTS = 4
        val DNS_CATEGORY_ORDER = listOf(
            "v4-loopback", "v4-linklocal", "v4-private", "v4-public",
            "v6-loopback", "v6-linklocal", "v6-private", "v6-public",
            "unknown-unknown",
        )
    }
}
