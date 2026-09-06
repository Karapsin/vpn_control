package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import java.security.MessageDigest
import java.nio.ByteBuffer

/** Frontend-only input. Its opening revision never advances after a failed save. */
internal data class DesktopDnsDraft(
    val controllerId: String?,
    val revision: Long,
    val mode: DnsMode,
    val endpoint: String,
    val failure: ControlCode? = null,
    val openingId: String = UUID.randomUUID().toString(),
) {
    fun values(): Map<String, ControlValue> = mapOf(
        "dns.mode" to ControlValue.Text(when (mode) {
            DnsMode.AUTOMATIC -> "automatic"
            DnsMode.CUSTOM_DOH -> "custom-doh"
            DnsMode.CUSTOM_DOT -> "custom-dot"
        }),
        "dns.endpoint" to ControlValue.Text(endpoint),
    )

    fun request(): ControlRequest = frontendSettingsRequest(openingId, controllerId, revision, values())

    override fun toString(): String = "DesktopDnsDraft(revision=$revision, input=<redacted>, failure=$failure)"

    companion object {
        fun from(result: ControlResult): DesktopDnsDraft {
            require(result.ok && result.controllerId != null)
            return from(result.controllerId, result.configurationRevision, result.data)
        }

        fun from(owner: String?, revision: Long, values: Map<String, ControlValue>): DesktopDnsDraft = DesktopDnsDraft(
            owner, revision, when ((values.getValue("dns.mode") as ControlValue.Text).value) {
                "automatic" -> DnsMode.AUTOMATIC
                "custom-doh" -> DnsMode.CUSTOM_DOH
                "custom-dot" -> DnsMode.CUSTOM_DOT
                else -> error("INCOMPATIBLE_PROTOCOL")
            }, (values.getValue("dns.endpoint") as ControlValue.Text).value)
    }
}

internal fun frontendSettingsRequest(openingId: String, controllerId: String?, revision: Long,
    values: Map<String, ControlValue>, inputIdentity: String = ControlProtocolCodec.encodeValues(values)): ControlRequest {
        val digest = MessageDigest.getInstance("SHA-256")
        for (value in listOf(openingId, controllerId.orEmpty(), revision.toString(), inputIdentity)) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            digest.update(ByteBuffer.allocate(4).putInt(bytes.size).array())
            digest.update(bytes)
        }
        return ControlRequest("settings-" + digest.digest().joinToString("") { "%02x".format(it) },
        ControlCommand(ControlOperationId.SETTINGS_APPLY,
            mapOf("input" to ControlValue.Text(ControlProtocolCodec.encodeValues(values)))),
        controllerId = controllerId, ifRevision = revision)
}

/** Shared remote submission; isolated previews reuse their existing service, never create an owner. */
internal suspend fun submitFrontendSettings(
    request: ControlRequest,
    session: com.kardinal.vpncontrol.control.ControlSession?,
    previewWrite: (Map<String, ControlValue>, Long?) -> DesktopControlWriteResponse,
): ControlCode = submitFrontendSettingsResult(request, session, previewWrite).code

internal suspend fun submitFrontendSettingsResult(
    request: ControlRequest,
    session: com.kardinal.vpncontrol.control.ControlSession?,
    previewWrite: (Map<String, ControlValue>, Long?) -> DesktopControlWriteResponse,
): ControlResult {
    if (session != null) return session.submit(request)
    val values = com.kardinal.vpncontrol.control.ControlSettingsLogic.parseRequestArguments(
        request.command.operation, request.command.arguments).getOrElse {
            return ControlResult(request.controllerId, request.requestId, ControlCode.INVALID_ARGUMENT, request.ifRevision ?: 0)
        }
    val committed = previewWrite(values, request.ifRevision)
    return ControlResult(request.controllerId, request.requestId,
        desktopGuiCommandFailure(committed.response) ?: ControlCode.OK, committed.metadata.configurationRevision,
        restartRequired = committed.metadata.restartRequired)
}

internal fun frontendSettingsNeedsRestart(group: DesktopSettingsDraftGroup, result: ControlResult): Boolean =
    group == DesktopSettingsDraftGroup.SSH && result.code == ControlCode.OK && result.final && result.restartRequired

internal enum class DesktopSettingsDraftGroup { REFRESH, VALIDATION, LANGUAGE, SSH, MODE }

/** Only the chosen settings group is retained, never unrelated credentials/configuration. */
internal data class DesktopSettingsDraft(
    val group: DesktopSettingsDraftGroup,
    val controllerId: String?, val revision: Long,
    val fields: Map<String, String>,
    val openingHours: Double = 3.0,
    val openingId: String = UUID.randomUUID().toString(),
    val failure: ControlCode? = null,
) {
    fun edit(key: String, value: String) = copy(fields = fields + (key to value))
    fun overlay(input: com.kardinal.vpncontrol.MainUiState): com.kardinal.vpncontrol.MainUiState {
        val state = input.copy(showRefreshPolicyDialog = false, showValidationSettingsDialog = false,
            showLanguageDialog = false, showHomeSshRouteDialog = false, showAppModeDialog = false)
        return when (group) {
        DesktopSettingsDraftGroup.MODE -> state.copy(showAppModeDialog = true,
            appMode = if (fields.getValue("mode") == "vpn") AppMode.VPN else AppMode.PROXY_ONLY)
        DesktopSettingsDraftGroup.LANGUAGE -> state.copy(showLanguageDialog = true,
            appLanguage = AppLanguage.entries.firstOrNull { it.code == fields["language"] }
                ?: AppLanguage.SYSTEM)
        DesktopSettingsDraftGroup.SSH -> state.copy(showHomeSshRouteDialog = true,
            homeSshEnabledDraft = fields.getValue("ssh.enabled").toBoolean(),
            homeSshHostDraft = fields.getValue("ssh.host"), homeSshPortDraft = fields.getValue("ssh.port"),
            homeSshUserDraft = fields.getValue("ssh.user"), homeSshHostKeysDraft = fields.getValue("ssh.host-keys"),
            homeSshRelayPortDraft = fields.getValue("ssh.relay-port"))
        DesktopSettingsDraftGroup.VALIDATION -> state.copy(showValidationSettingsDialog = true, showRefreshPolicyDialog = false,
            validationTestUrlDraft = fields.getValue("validation.test-url"),
            validationBatchSizeDraft = fields.getValue("validation.batch-size"),
            validationSubscriptionRefreshConcurrencyDraft = fields.getValue("validation.subscription-refresh-concurrency"),
            validationRetryCountDraft = fields.getValue("validation.retry-count"),
            validationActiveVerificationWindowSizeDraft = fields.getValue("validation.active-verification-window-size"))
        DesktopSettingsDraftGroup.REFRESH -> state.copy(showRefreshPolicyDialog = true, showValidationSettingsDialog = false,
            subscriptionRefreshPolicyDraft = when (fields.getValue("refresh.policy")) {
                "off" -> SubscriptionRefreshPolicy.OFF
                "every-hour" -> SubscriptionRefreshPolicy.EVERY_HOUR
                else -> SubscriptionRefreshPolicy.CUSTOM
            }, subscriptionRefreshCustomHours = openingHours,
            subscriptionRefreshCustomHoursDraft = fields.getValue("refresh.custom-hours"),
            findBestAfterSubscriptionRefreshDraft = fields.getValue("refresh.find-best-after-refresh").toBoolean())
        }
    }
    fun values(): Result<Map<String, ControlValue>> = runCatching {
        val local = overlay(com.kardinal.vpncontrol.MainUiState())
        if (group == DesktopSettingsDraftGroup.MODE) {
            mapOf("mode" to ControlValue.Text(fields.getValue("mode")))
        } else if (group == DesktopSettingsDraftGroup.LANGUAGE) {
            mapOf("language" to ControlValue.Text(fields.getValue("language")))
        } else if (group == DesktopSettingsDraftGroup.SSH) {
            val raw = com.kardinal.vpncontrol.HomeSshRouteLogic.fromDraft(local).getOrThrow()
            // Owner validates credentials and normalizes host/keys; never assume key availability here.
            mapOf("ssh.enabled" to ControlValue.BooleanValue(raw.enabled),
                "ssh.host" to ControlValue.Text(raw.host), "ssh.port" to ControlValue.IntegerValue(raw.port.toLong()),
                "ssh.user" to ControlValue.Text(raw.user), "ssh.relay-port" to ControlValue.IntegerValue(raw.relayPort.toLong()),
                "ssh.host-keys" to ControlValue.ArrayValue(raw.hostKeys.map(ControlValue::Text)))
        } else if (group == DesktopSettingsDraftGroup.VALIDATION) {
            val normalized = com.kardinal.vpncontrol.MainDraftLogic.resolveValidationSettingsSave(local).settings
            mapOf("validation.test-url" to ControlValue.Text(normalized.testUrl),
                "validation.batch-size" to ControlValue.IntegerValue(normalized.batchSize.toLong()),
                "validation.subscription-refresh-concurrency" to ControlValue.IntegerValue(normalized.subscriptionRefreshConcurrency.toLong()),
                "validation.retry-count" to ControlValue.IntegerValue(normalized.retryCount.toLong()),
                "validation.active-verification-window-size" to ControlValue.IntegerValue(normalized.activeVerificationWindowSize.toLong()))
        } else {
            val normalized = com.kardinal.vpncontrol.MainCommandLogic.resolveSubscriptionRefreshPolicySave(local).getOrThrow()
            mapOf("refresh.policy" to ControlValue.Text(fields.getValue("refresh.policy")),
                "refresh.custom-hours" to ControlValue.DecimalValue(normalized.resolvedHours),
                "refresh.find-best-after-refresh" to ControlValue.BooleanValue(normalized.findBestAfterRefresh))
        }
    }
    fun request(): Result<ControlRequest> = values().map { frontendSettingsRequest(openingId, controllerId, revision, it,
        ControlProtocolCodec.encodeValues(fields.mapValues { (_, value) -> ControlValue.Text(value) })) }
    override fun toString() = "DesktopSettingsDraft(group=$group, revision=$revision, input=<redacted>)"

    companion object {
        fun from(group: DesktopSettingsDraftGroup, result: ControlResult): DesktopSettingsDraft {
            require(result.ok)
            val prefix = when (group) {
                DesktopSettingsDraftGroup.REFRESH -> "refresh."
                DesktopSettingsDraftGroup.VALIDATION -> "validation."
                DesktopSettingsDraftGroup.LANGUAGE -> "language"
                DesktopSettingsDraftGroup.SSH -> "ssh."
                DesktopSettingsDraftGroup.MODE -> "mode"
            }
            val fields = result.data.filterKeys { it.startsWith(prefix) }.mapValues { (_, value) -> when (value) {
                is ControlValue.Text -> value.value
                is ControlValue.IntegerValue -> value.value.toString()
                is ControlValue.DecimalValue -> value.value.toString()
                is ControlValue.BooleanValue -> value.value.toString()
                is ControlValue.ArrayValue -> value.values.joinToString("\n") { (it as ControlValue.Text).value }
                else -> error("INCOMPATIBLE_PROTOCOL")
            } }
            return DesktopSettingsDraft(group, result.controllerId, result.configurationRevision, fields,
                fields["refresh.custom-hours"]?.toDouble() ?: 3.0)
        }
    }
}
