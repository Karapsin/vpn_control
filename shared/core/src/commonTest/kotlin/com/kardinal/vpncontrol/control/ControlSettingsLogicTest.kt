package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.PersistedState
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ControlSettingsLogicTest {
    @Test
    fun typedRequestsUseStrictArgumentsAndTransferredContent() {
        val set = com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SET
        val apply = com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_APPLY
        val patch = mapOf("validation.batch-size" to ControlValue.IntegerValue(7))
        assertEquals(patch, ControlSettingsLogic.parseRequestArguments(set,
            mapOf("key" to text("validation.batch-size"), "value" to text("7"))).getOrThrow())
        assertEquals(patch, ControlSettingsLogic.parseRequestArguments(apply,
            mapOf("input" to text("{\"validation.batch-size\":7}"))).getOrThrow())
        assertTrue(ControlSettingsLogic.parseRequestArguments(apply,
            mapOf("input" to text("/private/controller-settings.json"))).isFailure)
        assertTrue(ControlSettingsLogic.parseRequestArguments(apply,
            mapOf("input" to text("{}"), "extra" to text("value"))).isFailure)
        assertTrue(ControlSettingsLogic.parseRequestArguments(set,
            mapOf("key" to text("validation.batch-size"), "value" to ControlValue.IntegerValue(7))).isFailure)
    }

    @Test
    fun terminalValuesPreserveTypesAndRejectTrailingObjectMembers() {
        assertEquals(ControlValue.BooleanValue(true), ControlSettingsLogic.parseTerminalValue("ssh.enabled", "true").getOrThrow())
        assertEquals(ControlValue.IntegerValue(4), ControlSettingsLogic.parseTerminalValue("validation.batch-size", "4").getOrThrow())
        assertEquals(text("https://dns.example"), ControlSettingsLogic.parseTerminalValue("dns.endpoint", "https://dns.example").getOrThrow())
        assertTrue(ControlSettingsLogic.parseTerminalValue("ssh.enabled", "true,\"extra\":false").isFailure)
        assertTrue(ControlSettingsLogic.parseTerminalValue("ssh.enabled", "true,\"value\":false").isFailure)
        assertTrue(ControlSettingsLogic.parseTerminalValue("unknown", "true").isFailure)
    }

    @Test
    fun combinedDnsPatchIsAtomicAndIndependentOfFieldOrder() {
        val patch = linkedMapOf("dns.mode" to text("custom-doh"), "dns.endpoint" to text("https://dns.example.test"))
        val forward = configuration(patch)
        val reversed = configuration(patch.entries.reversed().associate { it.toPair() })
        assertEquals(forward, reversed)
        assertEquals(DnsMode.CUSTOM_DOH, forward.state.dnsSettings.mode)
        assertEquals("https://dns.example.test/dns-query", forward.state.dnsSettings.endpoint)
        assertEquals(text(forward.state.dnsSettings.endpoint), forward.normalized["dns.endpoint"])
    }

    @Test
    fun invalidPatchNeverReturnsPartiallyChangedState() {
        val state = PersistedState(isVpnRunning = true, successfulStarts = 10)
        val plan = ControlSettingsLogic.plan(state, mapOf(
            "mode" to text("proxy-only"), "dns.mode" to text("custom-dot"),
            "dns.endpoint" to text("tls://SECRET@dns.example.test/path"),
        ), ControlPlatform.LINUX, false)
        assertEquals(ControlCode.INVALID_ARGUMENT, assertIs<ControlSettingsPlan.Rejected>(plan).code)
        assertFalse(plan.toString().contains("SECRET"))
        assertEquals(AppMode.VPN, state.appMode)
        assertTrue(state.isVpnRunning)
    }

    @Test
    fun savingModeDoesNotRewriteRuntimeOrSessionFields() {
        val state = PersistedState(isVpnRunning = true, runtimeConfigJson = "active", successfulStarts = 7,
            sessionStartedAtEpochMillis = 100, runtimeStartSequence = 4)
        val plan = assertIs<ControlSettingsPlan.Configuration>(ControlSettingsLogic.plan(
            state, mapOf("mode" to text("proxy-only")), ControlPlatform.LINUX, false))
        assertEquals(state.copy(appMode = AppMode.PROXY_ONLY), plan.state)
    }

    @Test
    fun sharedValidationNormalizationAndFractionalRefreshArePreserved() {
        val plan = configuration(mapOf(
            "validation.batch-size" to integer(0), "validation.subscription-refresh-concurrency" to integer(999),
            "validation.retry-count" to integer(-1), "validation.active-verification-window-size" to integer(0),
            "refresh.custom-hours" to ControlValue.DecimalValue(1.5),
        ))
        assertEquals(1, plan.state.validationSettings.batchSize)
        assertEquals(8, plan.state.validationSettings.subscriptionRefreshConcurrency)
        assertEquals(0, plan.state.validationSettings.retryCount)
        assertEquals(1, plan.state.validationSettings.activeVerificationWindowSize)
        assertEquals(1.5, plan.state.subscriptionRefreshCustomHours)
    }

    @Test
    fun unknownDormantPrivateAndWrongTypedKeysFailClosed() {
        for (patch in listOf(
            mapOf("SECRET" to text("value")), mapOf("ssh.private-key" to text("SECRET")),
            mapOf("subscriptionHwid" to text("value")), mapOf("session-stats-enabled" to ControlValue.BooleanValue(true)),
            mapOf("validation.batch-size" to text("3")), mapOf("validation.batch-size" to ControlValue.DecimalValue(3.5)),
            mapOf("validation.batch-size" to ControlValue.IntegerValue(Long.MAX_VALUE)),
            mapOf("ssh.enabled" to text("true")), mapOf("language" to text("invalid-language")),
            mapOf("ssh.host-keys" to ControlValue.ArrayValue(listOf(integer(1)))),
        )) {
            val result = assertIs<ControlSettingsPlan.Rejected>(ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.LINUX, false))
            assertEquals(ControlCode.INVALID_ARGUMENT, result.code)
            assertFalse(result.toString().contains("SECRET"))
        }
    }

    @Test
    fun macVpnFailsExplicitlyWithoutChangingThePersistedDefaultForOtherSettings() {
        val result = ControlSettingsLogic.plan(PersistedState(), mapOf("mode" to text("vpn")), ControlPlatform.MACOS, false)
        assertEquals(ControlCode.UNSUPPORTED, assertIs<ControlSettingsPlan.Rejected>(result).code)
        val language = ControlSettingsLogic.plan(PersistedState(), mapOf("language" to text("en")), ControlPlatform.MACOS, false)
        assertEquals(AppMode.VPN, assertIs<ControlSettingsPlan.Configuration>(language).state.appMode)
    }

    @Test
    fun autostartHasASeparatePlatformTransaction() {
        val patch = mapOf("autostart" to ControlValue.BooleanValue(true))
        assertIs<ControlSettingsPlan.Autostart>(ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.WINDOWS, false))
        assertEquals(ControlCode.UNSUPPORTED, assertIs<ControlSettingsPlan.Rejected>(
            ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.ANDROID, false)).code)
        assertEquals(ControlCode.INVALID_ARGUMENT, assertIs<ControlSettingsPlan.Rejected>(
            ControlSettingsLogic.plan(PersistedState(), patch + ("language" to text("en")), ControlPlatform.LINUX, false)).code)
    }

    @Test
    fun enablingSshValidatesTheWholeProposalAndRequiresAnImportedCredential() {
        val patch = mapOf(
            "ssh.enabled" to ControlValue.BooleanValue(true), "ssh.host" to text("ssh://relay.example.test/"),
            "ssh.user" to text(" vpn "), "ssh.host-keys" to ControlValue.ArrayValue(listOf(text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey comment"))),
        )
        assertIs<ControlSettingsPlan.Rejected>(ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.LINUX, false))
        val plan = assertIs<ControlSettingsPlan.Configuration>(ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.LINUX, true))
        assertEquals("relay.example.test", plan.state.homeSshRouteSettings.host)
        assertEquals("vpn", plan.state.homeSshRouteSettings.user)
        assertEquals(0, plan.state.homeSshRouteSettings.credentialVersion)
    }

    @Test
    fun inspectionExposesOnlySupportedSettingsNotInternalFields() {
        assertEquals(ControlSettingsLogic.writableKeys - "autostart", ControlSettingsLogic.inspect(PersistedState()).keys)
    }

    private fun configuration(patch: Map<String, ControlValue>) = assertIs<ControlSettingsPlan.Configuration>(
        ControlSettingsLogic.plan(PersistedState(), patch, ControlPlatform.LINUX, false))
    private fun text(value: String) = ControlValue.Text(value)
    private fun integer(value: Int) = ControlValue.IntegerValue(value.toLong())
}
