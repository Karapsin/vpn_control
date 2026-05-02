package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile

object VlessParser {
    fun parseSubscription(rawBody: String): List<ProxyProfile> =
        ProxyParser.parseSubscription(rawBody)

    fun parseVlessLink(link: String): ProxyProfile =
        ProxyParser.parseVlessLink(link)

    fun encodeVlessLink(profile: ProxyProfile): String =
        ProxyParser.encodeVlessLink(profile)
}
