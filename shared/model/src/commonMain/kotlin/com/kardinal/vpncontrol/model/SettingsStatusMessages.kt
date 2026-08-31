package com.kardinal.vpncontrol.model

object SettingsStatusMessages {
    fun subscriptionAutoRefreshSet(
        policy: SubscriptionRefreshPolicy,
        customIntervalHours: Double,
    ): String = StatusMessageCodec.encode(
        StatusMessageKey.SUBSCRIPTION_AUTO_REFRESH_SET,
        policy.name,
        policy.effectiveIntervalMinutes(customIntervalHours)?.toString().orEmpty(),
    )

    fun validationSettingsSaved(settings: BenchmarkValidationSettings): String {
        val normalized = settings.normalized()
        return StatusMessageCodec.encode(
            StatusMessageKey.VALIDATION_SETTINGS_SAVED,
            normalized.testUrl.displayHost(),
            normalized.batchSize.toString(),
            normalized.subscriptionRefreshConcurrency.toString(),
            normalized.retryCount.toString(),
            normalized.activeVerificationWindowSize.toString(),
        )
    }

    fun customDnsSaved(enabled: Boolean): String =
        StatusMessageCodec.encode(if (enabled) StatusMessageKey.CUSTOM_DNS_SAVED else StatusMessageKey.CUSTOM_DNS_DISABLED)

    fun dnsSettingsSaved(mode: DnsMode): String = StatusMessageCodec.encode(
        if (mode == DnsMode.AUTOMATIC) {
            StatusMessageKey.SECURE_DNS_AUTOMATIC_SAVED
        } else {
            StatusMessageKey.CUSTOM_DNS_SAVED
        },
    )

    fun customDnsEndpointInvalid(): String =
        StatusMessageCodec.encode(StatusMessageKey.CUSTOM_DNS_ENDPOINT_INVALID)

    fun homeSshPrivateKeyImported(): String =
        StatusMessageCodec.encode(StatusMessageKey.HOME_SSH_PRIVATE_KEY_IMPORTED)

    fun homeSshPrivateKeyImportFailed(detail: String = ""): String =
        StatusMessageCodec.encode(StatusMessageKey.HOME_SSH_PRIVATE_KEY_IMPORT_FAILED, detail)

    fun homeSshSettingsInvalid(detail: String = ""): String =
        StatusMessageCodec.encode(StatusMessageKey.HOME_SSH_SETTINGS_INVALID, detail)

    fun homeSshRouteSaved(restartRequired: Boolean): String = StatusMessageCodec.encode(
        if (restartRequired) {
            StatusMessageKey.HOME_SSH_ROUTE_SAVED_RESTART_REQUIRED
        } else {
            StatusMessageKey.HOME_SSH_ROUTE_SAVED
        },
    )

    fun homeSshRouteRestarting(): String =
        StatusMessageCodec.encode(StatusMessageKey.HOME_SSH_ROUTE_RESTARTING)

    fun uiSettingVisibilityChanged(
        item: UiSettingsStatusItem,
        enabled: Boolean,
    ): String = StatusMessageCodec.encode(StatusMessageKey.UI_SETTING_VISIBILITY_CHANGED, item.name, enabled.toString())

    fun startOnLoginEnabled(): String =
        StatusMessageCodec.encode(StatusMessageKey.START_ON_LOGIN_ENABLED)

    fun startOnLoginDisabled(): String =
        StatusMessageCodec.encode(StatusMessageKey.START_ON_LOGIN_DISABLED)

    fun startupSettingUpdateFailed(detail: String = ""): String =
        StatusMessageCodec.encode(StatusMessageKey.STARTUP_SETTING_UPDATE_FAILED, detail)

    fun subscriptionHwidCleared(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_HWID_CLEARED)

    fun subscriptionHwidSaved(): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_HWID_SAVED)

    fun refreshSettingsSaveFailed(detail: String = ""): String =
        StatusMessageCodec.encode(StatusMessageKey.REFRESH_SETTINGS_SAVE_FAILED, detail)

    fun appModeChanged(mode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.APP_MODE_CHANGED, mode.name)

    fun connectionStoppedForAppMode(
        stoppedMode: AppMode,
        nextMode: AppMode,
    ): String = StatusMessageCodec.encode(StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE, stoppedMode.name, nextMode.name)
}
