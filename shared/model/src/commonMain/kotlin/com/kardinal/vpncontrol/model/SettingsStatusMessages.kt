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
            normalized.primaryUrl.displayHost(),
            normalized.secondaryUrl.displayHost(),
            normalized.batchSize.toString(),
            normalized.subscriptionRefreshConcurrency.toString(),
            normalized.retryCount.toString(),
        )
    }

    fun customDnsSaved(enabled: Boolean): String =
        StatusMessageCodec.encode(if (enabled) StatusMessageKey.CUSTOM_DNS_SAVED else StatusMessageKey.CUSTOM_DNS_DISABLED)

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
