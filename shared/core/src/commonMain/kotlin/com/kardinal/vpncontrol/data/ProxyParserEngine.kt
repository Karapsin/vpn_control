package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile

internal object ProxyParserEngine {
    fun parseSubscription(rawBody: String): List<ProxyProfile> =
        SubscriptionPayloadParser.parse(rawBody)

    internal fun supportsJsonSubscription(rawBody: String): Boolean {
        return JsonSubscriptionParser.parse(rawBody) != null
    }

    fun parseProxyLink(link: String): ProxyProfile =
        ProxyLinkParser.parseProxyLink(link)

    fun parseVlessLink(link: String): ProxyProfile =
        ProxyLinkParser.parseVlessLink(link)

    fun parseTrojanLink(link: String): ProxyProfile =
        ProxyLinkParser.parseTrojanLink(link)

    fun parseShadowsocksLink(link: String): ProxyProfile =
        ProxyLinkParser.parseShadowsocksLink(link)

    fun parseVmessLink(link: String): ProxyProfile =
        ProxyLinkParser.parseVmessLink(link)

    fun parseSocksLink(link: String): ProxyProfile =
        ProxyLinkParser.parseSocksLink(link)

    fun encodeProxyLink(profile: ProxyProfile): String =
        ProxyLinkEncoder.encodeProxyLink(profile)

    fun encodeVlessLink(profile: ProxyProfile): String =
        ProxyLinkEncoder.encodeVlessLink(profile)

}
