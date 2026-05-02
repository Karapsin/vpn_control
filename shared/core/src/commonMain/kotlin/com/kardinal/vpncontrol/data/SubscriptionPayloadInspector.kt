package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile

object SubscriptionPayloadInspector {
    private val genericChallengeMarkers = listOf(
        "ddos-guard",
        "captcha",
        "enable javascript",
        "just a moment",
        "attention required",
        "access denied",
        "liberty vpn",
    )

    fun detectPayloadError(body: String, contentType: String?): String? {
        val normalizedType = contentType
            ?.substringBefore(';')
            ?.trim()
            ?.lowercase()
            .orEmpty()
        val trimmed = body.trimStart()
        val lowercase = trimmed.lowercase()
        val looksLikeHtml = trimmed.startsWith("<!doctype html", ignoreCase = true) ||
            trimmed.startsWith("<html", ignoreCase = true)
        val looksLikeJson = trimmed.startsWith("{") || trimmed.startsWith("[")
        val looksLikeChallenge = genericChallengeMarkers.any { marker -> marker in lowercase }
        return when {
            trimmed.isBlank() ->
                "Subscription endpoint returned an empty response"
            normalizedType == "text/html" || looksLikeHtml ->
                "Subscription endpoint returned an HTML page instead of a subscription payload"
            looksLikeChallenge ->
                "Subscription endpoint returned a challenge or website page instead of a subscription payload"
            looksLikeJson && !ProxyParser.supportsJsonSubscription(trimmed) ->
                "Subscription endpoint returned JSON instead of a subscription payload"
            else -> null
        }
    }

    fun invalidPayloadMessage(error: Throwable): String {
        val detail = error.message?.trim().orEmpty()
        if (detail.isBlank()) {
            return "Subscription endpoint returned an invalid subscription payload"
        }
        val normalized = detail.lowercase()
        return when {
            "base-64" in normalized ||
                "subscription format" in normalized ||
                "supported proxy link list" in normalized ||
                "not recognized" in normalized ->
                "Subscription endpoint returned an invalid subscription payload"
            else ->
                "Subscription endpoint returned an invalid subscription payload: $detail"
        }
    }

    fun parsedProfileError(
        profiles: List<ProxyProfile>,
        responseHeaders: Map<String, String>,
    ): String? {
        if (profiles.isEmpty() || profiles.any { !it.isDeviceBindingPlaceholder() }) {
            return null
        }
        return when {
            responseHeaders.hasHeader("x-hwid-max-devices-reached") ->
                "Subscription device limit reached. Reset provider devices or set an authorized x-hwid."
            responseHeaders.hasHeader("x-hwid-not-supported") ->
                "Subscription requires a supported x-hwid header."
            responseHeaders.hasHwidHint() ->
                "Subscription returned a device-binding placeholder. Check provider HWID/device limit."
            else ->
                "Subscription endpoint returned disabled placeholder locations"
        }
    }

    private fun ProxyProfile.isDeviceBindingPlaceholder(): Boolean {
        return server == "0.0.0.0" && serverPort <= 1
    }

    private fun Map<String, String>.hasHwidHint(): Boolean {
        return keys.any { key -> key.startsWith("x-hwid", ignoreCase = true) } ||
            values.any { value -> "x-hwid" in value.lowercase() }
    }

    private fun Map<String, String>.hasHeader(name: String): Boolean {
        return keys.any { key -> key.equals(name, ignoreCase = true) }
    }
}
