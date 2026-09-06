package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.HomeSshRouteLogic
import com.kardinal.vpncontrol.data.SecureDnsEndpointParser
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.normalizeSubscriptionRefreshCustomHours

sealed interface ControlSettingsPlan {
    data class Configuration(val state: PersistedState, val normalized: Map<String, ControlValue>) : ControlSettingsPlan {
        override fun toString(): String = "Configuration(<redacted>)"
    }
    data class Autostart(val enabled: Boolean) : ControlSettingsPlan
    data class Rejected(val code: ControlCode, val field: String? = null) : ControlSettingsPlan
}

/** Shared atomic proposal validation. The adapter persists only a successful plan. */
object ControlSettingsLogic {
    /** `input` is transferred JSON content, never a path on the controller filesystem. */
    fun parseRequestArguments(
        operation: com.kardinal.vpncontrol.model.ControlOperationId,
        arguments: Map<String, ControlValue>,
    ): Result<Map<String, ControlValue>> = runCatching {
        fun text(key: String) = (arguments[key] as? ControlValue.Text)?.value
            ?: throw IllegalArgumentException("INVALID_ARGUMENT")
        when (operation) {
            com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SET -> {
                require(arguments.keys == setOf("key", "value"))
                val key = text("key")
                mapOf(key to parseTerminalValue(key, text("value")).getOrThrow())
            }
            com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_APPLY -> {
                require(arguments.keys == setOf("input"))
                ControlProtocolCodec.decodeValues(text("input"))
            }
            else -> throw IllegalArgumentException("UNSUPPORTED")
        }
    }

    fun parseTerminalValue(key: String, raw: String): Result<ControlValue> = runCatching {
        require(key in writableKeys)
        if (key in setOf("mode", "language", "dns.mode", "dns.endpoint", "ssh.host", "ssh.user", "refresh.policy", "validation.test-url")) {
            ControlValue.Text(raw)
        } else {
            val values = ControlProtocolCodec.decodeValues("{\"value\":$raw}")
            require(values.keys == setOf("value"))
            values.getValue("value")
        }
    }
    val writableKeys: Set<String> = setOf(
        "mode", "language", "dns.mode", "dns.endpoint", "ssh.enabled", "ssh.host", "ssh.port",
        "ssh.user", "ssh.host-keys", "ssh.relay-port", "refresh.policy", "refresh.custom-hours",
        "refresh.find-best-after-refresh", "validation.test-url", "validation.batch-size",
        "validation.subscription-refresh-concurrency", "validation.retry-count",
        "validation.active-verification-window-size", "autostart",
    )

    fun plan(
        current: PersistedState,
        patch: Map<String, ControlValue>,
        platform: ControlPlatform,
        credentialAvailable: Boolean,
    ): ControlSettingsPlan {
        // Do not echo an unknown user-controlled key into status/log output.
        if (patch.keys.any { it !in writableKeys }) return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT)
        if ("autostart" in patch) {
            if (patch.size != 1) return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT, "autostart")
            if (!ControlOperationRegistry.platformSupports("autostart", platform)) {
                return ControlSettingsPlan.Rejected(ControlCode.UNSUPPORTED, "autostart")
            }
            val enabled = (patch["autostart"] as? ControlValue.BooleanValue)?.value
                ?: return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT, "autostart")
            return ControlSettingsPlan.Autostart(enabled)
        }
        var proposed = current
        for ((key, value) in patch) {
            try {
                proposed = when (key) {
                    "mode" -> {
                        val mode = when (value.text()) {
                            "vpn" -> AppMode.VPN
                            "proxy-only" -> AppMode.PROXY_ONLY
                            else -> invalid()
                        }
                        if (mode == AppMode.VPN && !ControlOperationRegistry.platformSupports("mode.vpn", platform)) {
                            return ControlSettingsPlan.Rejected(ControlCode.UNSUPPORTED, key)
                        }
                        proposed.copy(appMode = mode)
                    }
                    "language" -> proposed.copy(appLanguage = when (val code = value.text()) {
                        "system" -> AppLanguage.SYSTEM
                        else -> AppLanguage.entries.firstOrNull { it != AppLanguage.SYSTEM && it.code == code } ?: invalid()
                    })
                    "dns.mode" -> proposed.copy(dnsSettings = proposed.dnsSettings.copy(mode = when (value.text()) {
                        "automatic" -> DnsMode.AUTOMATIC
                        "custom-doh" -> DnsMode.CUSTOM_DOH
                        "custom-dot" -> DnsMode.CUSTOM_DOT
                        else -> invalid()
                    }))
                    "dns.endpoint" -> proposed.copy(dnsSettings = proposed.dnsSettings.copy(endpoint = value.text()))
                    "ssh.enabled" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(enabled = value.boolean()))
                    "ssh.host" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(host = value.text()))
                    "ssh.port" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(port = value.integer()))
                    "ssh.user" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(user = value.text()))
                    "ssh.host-keys" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(hostKeys = value.strings()))
                    "ssh.relay-port" -> proposed.copy(homeSshRouteSettings = proposed.homeSshRouteSettings.copy(relayPort = value.integer()))
                    "refresh.policy" -> proposed.copy(subscriptionRefreshPolicy = when (value.text()) {
                        "off" -> SubscriptionRefreshPolicy.OFF
                        "every-hour" -> SubscriptionRefreshPolicy.EVERY_HOUR
                        "custom" -> SubscriptionRefreshPolicy.CUSTOM
                        else -> invalid()
                    })
                    "refresh.custom-hours" -> proposed.copy(subscriptionRefreshCustomHours = normalizeSubscriptionRefreshCustomHours(value.number()))
                    "refresh.find-best-after-refresh" -> proposed.copy(findBestAfterSubscriptionRefresh = value.boolean())
                    "validation.test-url" -> proposed.copy(validationSettings = proposed.validationSettings.copy(testUrl = value.text()))
                    "validation.batch-size" -> proposed.copy(validationSettings = proposed.validationSettings.copy(batchSize = value.integer()))
                    "validation.subscription-refresh-concurrency" -> proposed.copy(validationSettings = proposed.validationSettings.copy(subscriptionRefreshConcurrency = value.integer()))
                    "validation.retry-count" -> proposed.copy(validationSettings = proposed.validationSettings.copy(retryCount = value.integer()))
                    "validation.active-verification-window-size" -> proposed.copy(validationSettings = proposed.validationSettings.copy(activeVerificationWindowSize = value.integer()))
                    else -> invalid()
                }
            } catch (_: IllegalArgumentException) {
                return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT, key)
            }
        }
        // Validate groups after all fields are applied: JSON object order must not matter.
        if (patch.keys.any { it.startsWith("dns.") }) {
            val dns = SecureDnsEndpointParser.normalize(proposed.dnsSettings).getOrNull()
                ?: return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT, "dns.endpoint")
            proposed = proposed.copy(dnsSettings = dns)
        }
        if (patch.keys.any { it.startsWith("ssh.") }) {
            val ssh = HomeSshRouteLogic.validate(proposed.homeSshRouteSettings, credentialAvailable).getOrNull()
                ?: return ControlSettingsPlan.Rejected(ControlCode.INVALID_ARGUMENT, "ssh.enabled")
            proposed = proposed.copy(homeSshRouteSettings = ssh)
        }
        if (patch.keys.any { it.startsWith("validation.") }) {
            proposed = proposed.copy(validationSettings = proposed.validationSettings.normalized())
        }
        val normalized = inspect(proposed).filterKeys { it in patch }
        return ControlSettingsPlan.Configuration(proposed, normalized)
    }

    /** Explicit settings inspection, not the redacted status/log projection. No private keys. */
    fun inspect(state: PersistedState): Map<String, ControlValue> = linkedMapOf(
        "mode" to text(if (state.appMode == AppMode.VPN) "vpn" else "proxy-only"),
        "language" to text(if (state.appLanguage == AppLanguage.SYSTEM) "system" else state.appLanguage.code),
        "dns.mode" to text(when (state.dnsSettings.mode) {
            DnsMode.AUTOMATIC -> "automatic"
            DnsMode.CUSTOM_DOH -> "custom-doh"
            DnsMode.CUSTOM_DOT -> "custom-dot"
        }),
        "dns.endpoint" to text(state.dnsSettings.endpoint),
        "ssh.enabled" to boolean(state.homeSshRouteSettings.enabled),
        "ssh.host" to text(state.homeSshRouteSettings.host),
        "ssh.port" to integer(state.homeSshRouteSettings.port),
        "ssh.user" to text(state.homeSshRouteSettings.user),
        "ssh.host-keys" to ControlValue.ArrayValue(state.homeSshRouteSettings.hostKeys.map(::text)),
        "ssh.relay-port" to integer(state.homeSshRouteSettings.relayPort),
        "refresh.policy" to text(when (state.subscriptionRefreshPolicy) {
            SubscriptionRefreshPolicy.OFF -> "off"
            SubscriptionRefreshPolicy.EVERY_HOUR -> "every-hour"
            SubscriptionRefreshPolicy.CUSTOM -> "custom"
        }),
        "refresh.custom-hours" to ControlValue.DecimalValue(normalizeSubscriptionRefreshCustomHours(state.subscriptionRefreshCustomHours)),
        "refresh.find-best-after-refresh" to boolean(state.findBestAfterSubscriptionRefresh),
        "validation.test-url" to text(state.validationSettings.testUrl),
        "validation.batch-size" to integer(state.validationSettings.batchSize),
        "validation.subscription-refresh-concurrency" to integer(state.validationSettings.subscriptionRefreshConcurrency),
        "validation.retry-count" to integer(state.validationSettings.retryCount),
        "validation.active-verification-window-size" to integer(state.validationSettings.activeVerificationWindowSize),
    )

    private fun ControlValue.text(): String = (this as? ControlValue.Text)?.value ?: invalid()
    private fun ControlValue.boolean(): Boolean = (this as? ControlValue.BooleanValue)?.value ?: invalid()
    private fun ControlValue.integer(): Int = (this as? ControlValue.IntegerValue)?.value
        ?.takeIf { it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() }?.toInt() ?: invalid()
    private fun ControlValue.number(): Double = when (this) {
        is ControlValue.IntegerValue -> value.toDouble()
        is ControlValue.DecimalValue -> value
        else -> invalid()
    }
    private fun ControlValue.strings(): List<String> = (this as? ControlValue.ArrayValue)?.values?.map { it.text() } ?: invalid()
    private fun text(value: String) = ControlValue.Text(value)
    private fun boolean(value: Boolean) = ControlValue.BooleanValue(value)
    private fun integer(value: Int) = ControlValue.IntegerValue(value.toLong())
    private fun invalid(): Nothing = throw IllegalArgumentException("INVALID_ARGUMENT")
}
