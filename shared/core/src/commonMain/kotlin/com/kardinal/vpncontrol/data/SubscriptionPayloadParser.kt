package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile

internal object SubscriptionPayloadParser {
    fun parse(rawBody: String): List<ProxyProfile> {
        JsonSubscriptionParser.parse(rawBody)?.let { return it }

        val directLines = rawBody.directLinkLines()
        if (directLines.any(ProxyLinkParser::looksLikeSupportedLink)) {
            return ProxyLinkParser.parseProxyLinkLines(directLines)
        }

        ClashSubscriptionParser.parse(rawBody)?.let { return it }

        val decoded = runCatching { decodeLooseBase64(rawBody.encodeToByteArray()) }
            .getOrElse { unrecognizedPayload() }
        JsonSubscriptionParser.parse(decoded)?.let { return it }
        ClashSubscriptionParser.parse(decoded)?.let { return it }

        val decodedLines = decoded.directLinkLines()
        if (decodedLines.any(ProxyLinkParser::looksLikeSupportedLink)) {
            return ProxyLinkParser.parseProxyLinkLines(decodedLines)
        }

        unrecognizedPayload()
    }

    private fun String.directLinkLines(): List<String> {
        return lines().map { it.trim() }.filter { it.isNotBlank() }
    }

    private fun unrecognizedPayload(): Nothing {
        error("Subscription format is not recognized as a supported proxy link list")
    }
}
