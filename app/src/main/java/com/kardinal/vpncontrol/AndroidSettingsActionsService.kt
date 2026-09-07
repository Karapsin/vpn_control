package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.SettingsStatusMessages
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
    private val credentialStore: com.kardinal.vpncontrol.data.AndroidHomeSshCredentialStore? = null,
    private val updateHomeSshRouteSettings: suspend (com.kardinal.vpncontrol.model.HomeSshRouteSettings) -> Unit = {},
    private val launchMutation: (suspend () -> Unit) -> Unit = launch,
    private val importKey: (suspend (String) -> com.kardinal.vpncontrol.model.ControlResult)? = null,
    private val homeSshPendingRestart: suspend () -> Boolean? = { null },
    private val sshDraft: AndroidSshDraftControl? = null,
) {
    fun toggleDnsDialog() {
        controller.toggleDnsDialog()
    }

    fun toggleHomeSshRouteDialog() {
        if (sshDraft != null) {
            if (controller.currentState().showHomeSshRouteDialog) {
                sshDraft.close()
                controller.update { it.copy(showHomeSshRouteDialog = false, homeSshDraftFailure = null) }
            } else launch {
                val settings = sshDraft.open()
                controller.update { it.copy(showHomeSshRouteDialog = true, homeSshDraftFailure = null,
                    homeSshEnabledDraft = settings.enabled, homeSshHostDraft = settings.host,
                    homeSshPortDraft = settings.port.toString(), homeSshUserDraft = settings.user,
                    homeSshHostKeysDraft = settings.hostKeys.joinToString("\n"), homeSshRelayPortDraft = settings.relayPort.toString()) }
            }
            return
        }
        controller.update { state ->
            if (state.showHomeSshRouteDialog) {
                state.copy(showHomeSshRouteDialog = false, homeSshDraftFailure = null)
            } else {
                val settings = state.homeSshRouteSettings
                state.copy(
                    showHomeSshRouteDialog = true,
                    homeSshDraftFailure = null,
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

    fun updateHomeSshDraft(transform: (MainUiState) -> MainUiState) {
        controller.update { transform(it).copy(homeSshDraftFailure = null) }
    }

    private suspend fun reportHomeSshDraftFailure(message: String) {
        controller.update { it.copy(homeSshDraftFailure = message) }
        updateStatus(message)
    }

    fun importHomeSshPrivateKey(content: String) {
        // The owner operation acquires the shared mutation lease itself.
        launch {
            val result = try {
                sshDraft?.importKey(content) ?: (importKey ?: error("UNSUPPORTED"))(content)
            } catch (_: Exception) {
                // Provider/IO exceptions can contain private input or sandbox paths.
                // The draft keeps the original request so explicit retry can recover it.
                reportHomeSshDraftFailure(SettingsStatusMessages.homeSshPrivateKeyImportFailed("OUTCOME_UNKNOWN"))
                return@launch
            }
            if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK) {
                reportHomeSshDraftFailure(SettingsStatusMessages.homeSshPrivateKeyImportFailed(result.code.wireName))
                return@launch
            }
            controller.update { it.copy(showHomeSshRestartDialog = result.restartRequired, homeSshDraftFailure = null,
                homeSshRestartPending = result.restartRequired) }
            updateStatus(SettingsStatusMessages.homeSshPrivateKeyImported())
        }
    }

    fun saveHomeSshRoute() {
        if (sshDraft != null) {
            launch {
                val settings = HomeSshRouteLogic.fromDraft(controller.currentState()).getOrNull()
                if (settings == null) { reportHomeSshDraftFailure(SettingsStatusMessages.homeSshSettingsInvalid()); return@launch }
                val result = try { sshDraft.save(settings) } catch (_: Exception) {
                    reportHomeSshDraftFailure(SettingsStatusMessages.homeSshSettingsInvalid("OUTCOME_UNKNOWN")); return@launch
                }
                if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK) {
                    reportHomeSshDraftFailure(SettingsStatusMessages.homeSshSettingsInvalid(result.code.wireName)); return@launch
                }
                sshDraft.close()
                controller.update { it.copy(showHomeSshRouteDialog = false, homeSshDraftFailure = null,
                    showHomeSshRestartDialog = result.restartRequired, homeSshRestartPending = result.restartRequired) }
                updateStatus(SettingsStatusMessages.homeSshRouteSaved(result.restartRequired))
            }
            return
        }
        launchMutation mutation@{
            val state = controller.currentState()
            val resolved = HomeSshRouteLogic.fromDraft(state).mapCatching { settings ->
                HomeSshRouteLogic.validate(settings, credentialStore?.hasPrivateKey(settings.credentialVersion) == true).getOrThrow()
            }
            if (resolved.isFailure) {
                reportHomeSshDraftFailure(SettingsStatusMessages.homeSshSettingsInvalid("INVALID_ARGUMENT"))
                return@mutation
            }
            val settings = resolved.getOrThrow()
            updateHomeSshRouteSettings(settings)
            // The previous committed settings are not the active runtime settings:
            // a key import or earlier save may already be pending. Only a known
            // owner comparison may clear that warning (including a genuine revert).
            val restartRequired = try { homeSshPendingRestart() }
                catch (error: kotlinx.coroutines.CancellationException) { throw error }
                catch (_: Exception) { null } ?: true
            controller.update {
                it.copy(
                    showHomeSshRouteDialog = false,
                    homeSshDraftFailure = null,
                    showHomeSshRestartDialog = restartRequired,
                    homeSshRestartPending = restartRequired,
                )
            }
            updateStatus(SettingsStatusMessages.homeSshRouteSaved(restartRequired))
        }
    }

    fun dismissHomeSshRestartDialog() {
        controller.update { it.copy(showHomeSshRestartDialog = false) }
    }

    fun markHomeSshRestartApplied() {
        controller.update { it.copy(showHomeSshRestartDialog = false, homeSshRestartPending = false) }
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
        launchMutation { effectSink.handleWithinMutation(controller.setAppLanguage(language)) }
    }

    fun setAppMode(value: AppMode) {
        launchMutation mutation@{
            val state = controller.currentState()
            if (state.appMode == value) return@mutation
            if (state.isVpnRunning) {
                val stopResult = stopConnection()
                if (stopResult.isFailure) {
                    updateStatus(
                        stopResult.exceptionOrNull()?.message
                            ?: ConnectionStatusMessages.connectionStopFailed(state.appMode),
                    )
                    return@mutation
                }
                controller.update { it.copy(isVpnRunning = false) }
            }
            effectSink.handleWithinMutation(controller.setAppMode(value))
        }
    }

    fun onDnsDraftChanged(value: String) {
        controller.onDnsDraftChanged(value)
    }

    fun onDnsModeChanged(mode: DnsMode) {
        controller.onDnsModeChanged(mode)
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
        launchMutation { effectSink.handleWithinMutation(controller.saveSubscriptionRefreshPolicy()) }
    }

    fun saveValidationSettings() {
        launchMutation { effectSink.handleWithinMutation(controller.saveValidationSettings()) }
    }

    fun saveDns() {
        launchMutation { effectSink.handleWithinMutation(controller.saveDns()) }
    }

    fun postStatus(message: String) {
        launch { updateStatus(message) }
    }
}
