package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.GeneralStatusMessages
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateTransitions
import com.kardinal.vpncontrol.HomeSshRouteLogic
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput

internal class DesktopSettingsService(
    private val stateProvider: () -> MainUiState,
    private val autostartManager: DesktopAutostartManager,
    private val stopConnection: suspend (String) -> Result<Unit>,
    private val commitState: (MainUiState) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val homeSshCredentialStore: DesktopHomeSshCredentialStore? = null,
) {
    fun toggleDnsDialog() {
        updateState {
            if (it.showDnsDialog) {
                it.copy(showDnsDialog = false)
            } else {
                it.copy(
                    showDnsDialog = true,
                    dnsModeDraft = it.dnsSettings.mode,
                    customDnsEndpointDraft = it.dnsSettings.endpoint,
                )
            }
        }
    }

    fun toggleHomeSshRouteDialog() {
        updateState { state ->
            if (state.showHomeSshRouteDialog) {
                state.copy(showHomeSshRouteDialog = false)
            } else {
                val settings = state.homeSshRouteSettings
                state.copy(
                    showHomeSshRouteDialog = true,
                    homeSshEnabledDraft = settings.enabled,
                    homeSshHostDraft = settings.host,
                    homeSshPortDraft = settings.port.toString(),
                    homeSshUserDraft = settings.user,
                    homeSshHostKeysDraft = settings.hostKeys.joinToString("\n"),
                    homeSshRelayPortDraft = settings.relayPort.toString(),
                )
            }
        }
    }

    fun updateHomeSshDraft(transform: (MainUiState) -> MainUiState) = updateState(transform)

    fun importHomeSshPrivateKey(content: String) {
        runCatching {
            (homeSshCredentialStore ?: error("SSH Routing credential storage is unavailable"))
                .importPrivateKey(content)
        }
            .onSuccess {
                val state = stateProvider()
                val updated = state.homeSshRouteSettings.copy(
                    credentialVersion = state.homeSshRouteSettings.credentialVersion + 1L,
                )
                val restartRequired = state.isVpnRunning && updated.enabled
                commitState(
                    state.copy(
                        homeSshRouteSettings = state.homeSshRouteSettings.copy(
                            credentialVersion = updated.credentialVersion,
                        ),
                        showHomeSshRestartDialog = restartRequired,
                        homeSshRestartPending = restartRequired,
                    ).withStatus(SettingsStatusMessages.homeSshPrivateKeyImported()),
                )
            }
            .onFailure { error ->
                updateState {
                    it.withStatus(SettingsStatusMessages.homeSshPrivateKeyImportFailed(error.message.orEmpty()))
                }
            }
    }

    fun saveHomeSshRoute() {
        val state = stateProvider()
        val result = HomeSshRouteLogic.fromDraft(state).mapCatching { settings ->
            HomeSshRouteLogic.validate(settings, homeSshCredentialStore?.hasPrivateKey() == true).getOrThrow()
        }
        if (result.isFailure) {
            updateState {
                it.withStatus(SettingsStatusMessages.homeSshSettingsInvalid(result.exceptionOrNull()?.message.orEmpty()))
            }
            return
        }
        val settings = result.getOrThrow()
        val restartRequired = state.isVpnRunning &&
            HomeSshRouteLogic.runtimeFingerprint(settings) !=
            HomeSshRouteLogic.runtimeFingerprint(state.homeSshRouteSettings)
        commitState(
            state.copy(
                homeSshRouteSettings = settings,
                showHomeSshRouteDialog = false,
                showHomeSshRestartDialog = restartRequired,
                homeSshRestartPending = restartRequired,
            ).withStatus(SettingsStatusMessages.homeSshRouteSaved(restartRequired)),
        )
    }

    fun dismissHomeSshRestartDialog() {
        updateState { it.copy(showHomeSshRestartDialog = false) }
    }

    fun markHomeSshRestartApplied() {
        updateState { it.copy(showHomeSshRestartDialog = false, homeSshRestartPending = false) }
    }

    fun setDnsModeDraft(mode: DnsMode) {
        updateState { it.copy(dnsModeDraft = mode) }
    }

    fun setCustomDnsDraft(value: String) {
        updateState { it.copy(customDnsEndpointDraft = value.take(2048)) }
    }

    fun saveDns() {
        val state = stateProvider()
        val result = MainDraftLogic.resolveDnsSave(state)
        if (result.isFailure) {
            updateState { it.withStatus(SettingsStatusMessages.customDnsEndpointInvalid()) }
            return
        }
        val plan = result.getOrThrow()
        commitState(
            state.copy(
                dnsSettings = plan.settings,
                dnsModeDraft = plan.settings.mode,
                customDnsEndpointDraft = plan.settings.endpoint,
                showDnsDialog = false,
            ).withStatus(plan.statusMessage),
        )
    }

    fun setStartOnBootEnabled(enabled: Boolean) {
        val result = autostartManager.setEnabled(enabled)
        val actual = autostartManager.isEnabled()
        val status = if (result.isSuccess) {
            if (actual) {
                SettingsStatusMessages.startOnLoginEnabled()
            } else {
                SettingsStatusMessages.startOnLoginDisabled()
            }
        } else {
            SettingsStatusMessages.startupSettingUpdateFailed(result.exceptionOrNull()?.message.orEmpty())
        }
        updateState { it.copy(startOnBootEnabled = actual).withStatus(status) }
    }

    fun toggleAppModeDialog() {
        updateState { it.copy(showAppModeDialog = !it.showAppModeDialog) }
    }

    fun toggleRefreshPolicyDialog() {
        updateState(MainUiStateTransitions::toggleRefreshPolicyDialog)
    }

    fun toggleValidationSettingsDialog() {
        updateState(MainUiStateTransitions::toggleValidationSettingsDialog)
    }

    fun toggleLanguageDialog() {
        updateState { it.copy(showLanguageDialog = !it.showLanguageDialog) }
    }

    fun setAppLanguage(language: AppLanguage) {
        updateState {
            it.copy(appLanguage = language, showLanguageDialog = false).withStatus(
                GeneralStatusMessages.languageSet(if (language == AppLanguage.SYSTEM) "" else language.nativeName),
            )
        }
    }

    fun setSubscriptionHwid(value: String) {
        val normalized = value.trim()
        val status = if (normalized.isBlank()) {
            SettingsStatusMessages.subscriptionHwidCleared()
        } else {
            SettingsStatusMessages.subscriptionHwidSaved()
        }
        updateState { it.copy(subscriptionHwid = normalized).withStatus(status) }
    }

    fun setValidationTestUrlDraft(value: String) {
        updateState { it.copy(validationTestUrlDraft = value) }
    }

    fun setValidationBatchSizeDraft(value: String) {
        updateState { it.copy(validationBatchSizeDraft = value.filter(Char::isDigit).take(3)) }
    }

    fun setValidationSubscriptionRefreshConcurrencyDraft(value: String) {
        updateState {
            it.copy(validationSubscriptionRefreshConcurrencyDraft = value.filter(Char::isDigit).take(2))
        }
    }

    fun setValidationRetryCountDraft(value: String) {
        updateState { it.copy(validationRetryCountDraft = value.filter(Char::isDigit).take(3)) }
    }

    fun setValidationActiveVerificationWindowSizeDraft(value: String) {
        updateState {
            it.copy(validationActiveVerificationWindowSizeDraft = value.filter(Char::isDigit).take(2))
        }
    }

    fun saveValidationSettings() {
        val state = stateProvider()
        val plan = MainDraftLogic.resolveValidationSettingsSave(state)
        val settings = plan.settings
        commitState(
            state.copy(
                validationSettings = settings,
                validationTestUrlDraft = settings.testUrl,
                validationBatchSizeDraft = settings.batchSize.toString(),
                validationSubscriptionRefreshConcurrencyDraft = settings.subscriptionRefreshConcurrency.toString(),
                validationRetryCountDraft = settings.retryCount.toString(),
                validationActiveVerificationWindowSizeDraft = settings.activeVerificationWindowSize.toString(),
                showValidationSettingsDialog = false,
            ).withStatus(plan.statusMessage),
        )
    }

    fun saveSubscriptionRefreshPolicy() {
        val state = stateProvider()
        val resolution = MainCommandLogic.resolveSubscriptionRefreshPolicySave(state)
        if (resolution.isFailure) {
            updateState {
                it.withStatus(
                    resolution.exceptionOrNull()?.message ?: SettingsStatusMessages.refreshSettingsSaveFailed(),
                )
            }
            return
        }
        val saved = resolution.getOrThrow()
        commitState(
            state.copy(
                subscriptionRefreshPolicy = saved.policy,
                subscriptionRefreshPolicyDraft = saved.policy,
                findBestAfterSubscriptionRefresh = saved.findBestAfterRefresh,
                findBestAfterSubscriptionRefreshDraft = saved.findBestAfterRefresh,
                subscriptionRefreshCustomHours = saved.resolvedHours,
                subscriptionRefreshCustomHoursDraft = formatSubscriptionRefreshHoursInput(saved.resolvedHours),
                showRefreshPolicyDialog = false,
            ).withStatus(saved.statusMessage),
        )
    }

    suspend fun setAppMode(mode: AppMode) {
        val state = stateProvider()
        if (state.isVpnRunning && mode != state.appMode) {
            val stopResult = stopConnection(
                SettingsStatusMessages.connectionStoppedForAppMode(state.appMode, mode),
            )
            if (stopResult.isFailure) {
                return
            }
        }
        updateState { it.withStatus(SettingsStatusMessages.appModeChanged(mode)).copy(appMode = mode, showAppModeDialog = false) }
    }

    suspend fun toggleAppMode() {
        val nextMode = if (stateProvider().appMode == AppMode.VPN) {
            AppMode.PROXY_ONLY
        } else {
            AppMode.VPN
        }
        setAppMode(nextMode)
    }
}
