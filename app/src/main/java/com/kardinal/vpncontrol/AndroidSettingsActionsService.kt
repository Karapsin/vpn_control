package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy

internal class AndroidSettingsActionsService(
    private val controller: MainController,
    private val effectSink: AndroidControllerEffectSink,
    private val launch: (suspend () -> Unit) -> Unit,
    private val stopConnection: suspend () -> Result<Unit>,
    private val updateStatus: suspend (String) -> Unit,
    private val updateSessionStatsEnabled: suspend (Boolean) -> Unit,
    private val updateLiveTrafficStatsEnabled: suspend (Boolean) -> Unit,
    private val updateProfileTotalsEnabled: suspend (Boolean) -> Unit,
    private val updateLatencyHistoryEnabled: suspend (Boolean) -> Unit,
    private val updateConnectionLogEnabled: suspend (Boolean) -> Unit,
    private val updateConnectionTestToolsEnabled: suspend (Boolean) -> Unit,
) {
    fun toggleDnsDialog() {
        controller.toggleDnsDialog()
    }

    fun toggleUiSettingsDialog() {
        controller.toggleUiSettingsDialog()
    }

    fun setSessionStatsEnabled(enabled: Boolean) {
        controller.setSessionStatsEnabled(enabled)
        launch {
            updateSessionStatsEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.sessionStats(enabled))
        }
    }

    fun setLiveTrafficStatsEnabled(enabled: Boolean) {
        controller.setLiveTrafficStatsEnabled(enabled)
        launch {
            updateLiveTrafficStatsEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.liveTrafficStats(enabled))
        }
    }

    fun setProfileTotalsEnabled(enabled: Boolean) {
        controller.setProfileTotalsEnabled(enabled)
        launch {
            updateProfileTotalsEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.profileTotals(enabled))
        }
    }

    fun setLatencyHistoryEnabled(enabled: Boolean) {
        controller.setLatencyHistoryEnabled(enabled)
        launch {
            updateLatencyHistoryEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.latencyHistory(enabled))
        }
    }

    fun setConnectionLogEnabled(enabled: Boolean) {
        controller.setConnectionLogEnabled(enabled)
        launch {
            updateConnectionLogEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.connectionLog(enabled))
        }
    }

    fun setConnectionTestToolsEnabled(enabled: Boolean) {
        controller.setConnectionTestToolsEnabled(enabled)
        launch {
            updateConnectionTestToolsEnabled(enabled)
            updateStatus(UiSettingsStatusLogic.connectionTestTools(enabled))
        }
    }

    fun toggleAppModeDialog() {
        controller.toggleAppModeDialog()
    }

    fun toggleRefreshPolicyDialog() {
        controller.toggleRefreshPolicyDialog()
    }

    fun toggleValidationSettingsDialog() {
        controller.toggleValidationSettingsDialog()
    }

    fun toggleLanguageDialog() {
        controller.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        effectSink.handle(controller.setAppLanguage(language))
    }

    fun setAppMode(value: AppMode) {
        val state = controller.currentState()
        if (state.appMode == value) return
        if (state.isVpnRunning) {
            launch {
                val stopResult = stopConnection()
                if (stopResult.isFailure) {
                    updateStatus(
                        stopResult.exceptionOrNull()?.message
                            ?: ConnectionStatusMessages.connectionStopFailed(state.appMode),
                    )
                    return@launch
                }
                controller.update { it.copy(isVpnRunning = false) }
                effectSink.handle(controller.setAppMode(value))
            }
            return
        }
        effectSink.handle(controller.setAppMode(value))
    }

    fun onDnsDraftChanged(value: String) {
        controller.onDnsDraftChanged(value)
    }

    fun onCustomDnsEnabledChanged(enabled: Boolean) {
        controller.onCustomDnsEnabledChanged(enabled)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        controller.onSubscriptionRefreshPolicyDraftChanged(policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        controller.onFindBestAfterSubscriptionRefreshDraftChanged(enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        controller.onSubscriptionRefreshCustomHoursDraftChanged(value)
    }

    fun onValidationTestUrlDraftChanged(value: String) {
        controller.onValidationTestUrlDraftChanged(value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        controller.onValidationBatchSizeDraftChanged(value)
    }

    fun onValidationSubscriptionRefreshConcurrencyDraftChanged(value: String) {
        controller.onValidationSubscriptionRefreshConcurrencyDraftChanged(value)
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        controller.onValidationRetryCountDraftChanged(value)
    }

    fun onValidationActiveVerificationWindowSizeDraftChanged(value: String) {
        controller.onValidationActiveVerificationWindowSizeDraftChanged(value)
    }

    fun saveSubscriptionRefreshPolicy() {
        effectSink.handle(controller.saveSubscriptionRefreshPolicy())
    }

    fun saveValidationSettings() {
        effectSink.handle(controller.saveValidationSettings())
    }

    fun saveDns() {
        effectSink.handle(controller.saveDns())
    }

    fun postStatus(message: String) {
        launch { updateStatus(message) }
    }
}
