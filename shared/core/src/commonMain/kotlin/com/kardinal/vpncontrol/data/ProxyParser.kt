package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile

object ProxyParser {
    fun parseSubscription(rawBody: String): List<ProxyProfile> =
        ProxyParserEngine.parseSubscription(rawBody)

    internal fun supportsJsonSubscription(rawBody: String): Boolean =
        ProxyParserEngine.supportsJsonSubscription(rawBody)

    fun parseProxyLink(link: String): ProxyProfile =
        ProxyParserEngine.parseProxyLink(link)

    fun parseVlessLink(link: String): ProxyProfile =
        ProxyParserEngine.parseVlessLink(link)

    fun parseTrojanLink(link: String): ProxyProfile =
        ProxyParserEngine.parseTrojanLink(link)

    fun parseShadowsocksLink(link: String): ProxyProfile =
        ProxyParserEngine.parseShadowsocksLink(link)

    fun parseVmessLink(link: String): ProxyProfile =
        ProxyParserEngine.parseVmessLink(link)

    fun parseSocksLink(link: String): ProxyProfile =
        ProxyParserEngine.parseSocksLink(link)

    fun encodeProxyLink(profile: ProxyProfile): String =
        ProxyParserEngine.encodeProxyLink(profile)

    fun encodeVlessLink(profile: ProxyProfile): String =
        ProxyParserEngine.encodeVlessLink(profile)
}
