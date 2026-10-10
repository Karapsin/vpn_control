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
    private val commitAppMode: suspend (AppMode) -> com.kardinal.vpncontrol.model.ControlResult,
    private val dnsDraft: AndroidDnsDraftControl,
    private val refreshDraft: AndroidSettingsDraftControl,
    private val validationDraft: AndroidSettingsDraftControl,
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
        if (controller.currentState().showDnsDialog || dnsDraft.isOpenOrOpening) {
            dnsDraft.close()
            controller.update { it.copy(showDnsDialog = false) }
        } else {
            // Reserve this opening before the asynchronous frontend launch.
            val opening = dnsDraft.beginOpen()
            launch {
                val settings = try {
                    dnsDraft.open(opening) ?: return@launch
                } catch (_: OutOfMemoryError) {
                    if (dnsDraft.isCurrent(opening)) {
                        dnsDraft.close()
                        updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName)
                    }
                    return@launch
                } catch (_: Exception) {
                    if (dnsDraft.isCurrent(opening)) {
                        dnsDraft.close()
                        updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName)
                    }
                    return@launch
                }
                controller.update { it.copy(showDnsDialog = true, dnsModeDraft = settings.mode,
                    customDnsEndpointDraft = settings.endpoint) }
            }
        }
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
        if (controller.currentState().showRefreshPolicyDialog || refreshDraft.isOpenOrOpening) {
            refreshDraft.close()
            controller.update { it.copy(showRefreshPolicyDialog = false) }
        } else {
            val opening = refreshDraft.beginOpen()
            launch {
                val settings = try { refreshDraft.open(opening) ?: return@launch }
                catch (_: OutOfMemoryError) {
                    if (refreshDraft.isCurrent(opening)) { refreshDraft.close(); updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
                    return@launch
                } catch (_: Exception) {
                    if (refreshDraft.isCurrent(opening)) { refreshDraft.close(); updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
                    return@launch
                }
                controller.update { it.copy(showRefreshPolicyDialog = true, subscriptionRefreshPolicyDraft = settings.subscriptionRefreshPolicy,
                    subscriptionRefreshCustomHoursDraft = com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput(settings.subscriptionRefreshCustomHours),
                    findBestAfterSubscriptionRefreshDraft = settings.findBestAfterSubscriptionRefresh) }
            }
        }
    }

    fun toggleValidationSettingsDialog() {
        if (controller.currentState().showValidationSettingsDialog || validationDraft.isOpenOrOpening) {
            validationDraft.close()
            controller.update { it.copy(showValidationSettingsDialog = false) }
        } else {
            val opening = validationDraft.beginOpen()
            launch {
                val settings = try { validationDraft.open(opening) ?: return@launch }
                catch (_: OutOfMemoryError) {
                    if (validationDraft.isCurrent(opening)) { validationDraft.close(); updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
                    return@launch
                } catch (_: Exception) {
                    if (validationDraft.isCurrent(opening)) { validationDraft.close(); updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
                    return@launch
                }
                controller.update { it.copy(showValidationSettingsDialog = true, validationTestUrlDraft = settings.validationSettings.testUrl,
                    validationBatchSizeDraft = settings.validationSettings.batchSize.toString(),
                    validationSubscriptionRefreshConcurrencyDraft = settings.validationSettings.subscriptionRefreshConcurrency.toString(),
                    validationRetryCountDraft = settings.validationSettings.retryCount.toString(),
                    validationActiveVerificationWindowSizeDraft = settings.validationSettings.activeVerificationWindowSize.toString()) }
            }
        }
    }

    fun toggleLanguageDialog() {
        controller.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        launchMutation { effectSink.handleWithinMutation(controller.setAppLanguage(language)) }
    }

    fun setAppMode(value: AppMode) {
        // The owner admits and persists this proposal; a live runtime keeps its configuration.
        launch {
            val result = try {
                commitAppMode(value)
            } catch (_: OutOfMemoryError) {
                updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName)
                return@launch
            } catch (_: Exception) {
                updateStatus(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN.wireName)
                return@launch
            }
            val committed = result.ok || result.data["configurationCommitted"] ==
                com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true)
            if (committed) controller.update {
                it.copy(appMode = value, showAppModeDialog = if (result.ok) false else it.showAppModeDialog)
            }
            if (!result.ok) {
                updateStatus(result.code.wireName)
                return@launch
            }
            updateStatus(com.kardinal.vpncontrol.model.RoutingStatusMessages.connectionModeSet(value))
        }
    }
    fun onDnsDraftChanged(value: String) {
        dnsDraft.changed()
        controller.onDnsDraftChanged(value)
    }

    fun onDnsModeChanged(mode: DnsMode) {
        dnsDraft.changed()
        controller.onDnsModeChanged(mode)
    }

    fun onSubscriptionRefreshPolicyDraftChanged(policy: SubscriptionRefreshPolicy) {
        refreshDraft.changed()
        controller.onSubscriptionRefreshPolicyDraftChanged(policy)
    }

    fun onFindBestAfterSubscriptionRefreshDraftChanged(enabled: Boolean) {
        refreshDraft.changed()
        controller.onFindBestAfterSubscriptionRefreshDraftChanged(enabled)
    }

    fun onSubscriptionRefreshCustomHoursDraftChanged(value: String) {
        refreshDraft.changed()
        controller.onSubscriptionRefreshCustomHoursDraftChanged(value)
    }

    fun onValidationTestUrlDraftChanged(value: String) {
        validationDraft.changed()
        controller.onValidationTestUrlDraftChanged(value)
    }

    fun onValidationBatchSizeDraftChanged(value: String) {
        validationDraft.changed()
        controller.onValidationBatchSizeDraftChanged(value)
    }

    fun onValidationSubscriptionRefreshConcurrencyDraftChanged(value: String) {
        validationDraft.changed()
        controller.onValidationSubscriptionRefreshConcurrencyDraftChanged(value)
    }

    fun onValidationRetryCountDraftChanged(value: String) {
        validationDraft.changed()
        controller.onValidationRetryCountDraftChanged(value)
    }

    fun onValidationActiveVerificationWindowSizeDraftChanged(value: String) {
        validationDraft.changed()
        controller.onValidationActiveVerificationWindowSizeDraftChanged(value)
    }

    fun saveSubscriptionRefreshPolicy() {
        val token = refreshDraft.capture()
        val resolution = MainCommandLogic.resolveSubscriptionRefreshPolicySave(controller.currentState())
        val plan = resolution.getOrNull()
        if (plan == null) {
            launch { if (refreshDraft.isCurrent(token)) updateStatus(
                resolution.exceptionOrNull()?.message ?: SettingsStatusMessages.refreshSettingsSaveFailed()) }
            return
        }
        saveSettingsDraft(refreshDraft, token, mapOf(
            "refresh.policy" to com.kardinal.vpncontrol.model.ControlValue.Text(when (plan.policy) {
                SubscriptionRefreshPolicy.OFF -> "off"
                SubscriptionRefreshPolicy.EVERY_HOUR -> "every-hour"
                SubscriptionRefreshPolicy.CUSTOM -> "custom"
            }),
            "refresh.custom-hours" to com.kardinal.vpncontrol.model.ControlValue.DecimalValue(plan.resolvedHours),
            "refresh.find-best-after-refresh" to com.kardinal.vpncontrol.model.ControlValue.BooleanValue(plan.findBestAfterRefresh),
        ), plan.statusMessage) { controller.update { it.copy(showRefreshPolicyDialog = false) } }
    }

    fun saveValidationSettings() {
        val token = validationDraft.capture()
        val plan = MainDraftLogic.resolveValidationSettingsSave(controller.currentState())
        saveSettingsDraft(validationDraft, token, mapOf(
            "validation.test-url" to com.kardinal.vpncontrol.model.ControlValue.Text(plan.settings.testUrl),
            "validation.batch-size" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(plan.settings.batchSize.toLong()),
            "validation.subscription-refresh-concurrency" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(plan.settings.subscriptionRefreshConcurrency.toLong()),
            "validation.retry-count" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(plan.settings.retryCount.toLong()),
            "validation.active-verification-window-size" to com.kardinal.vpncontrol.model.ControlValue.IntegerValue(plan.settings.activeVerificationWindowSize.toLong()),
        ), plan.statusMessage) { controller.update { it.copy(showValidationSettingsDialog = false) } }
    }

    private fun saveSettingsDraft(
        draft: AndroidSettingsDraftControl,
        token: AndroidSettingsDraftControl.Token,
        patch: Map<String, com.kardinal.vpncontrol.model.ControlValue>,
        statusMessage: String,
        closeDialog: () -> Unit,
    ) {
        val attempt = try { draft.prepareSave(patch) }
        catch (_: OutOfMemoryError) {
            launch { if (draft.isCurrent(token)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
            return
        } catch (_: Exception) {
            launch { if (draft.isCurrent(token)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN.wireName) }
            return
        }
        launch {
            if (!draft.isCurrent(attempt)) return@launch
            val result = try { draft.save(attempt) }
            catch (_: OutOfMemoryError) {
                if (draft.isCurrent(attempt)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName)
                return@launch
            } catch (_: Exception) {
                if (draft.isCurrent(attempt)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN.wireName)
                return@launch
            }
            if (!draft.isCurrent(attempt)) return@launch
            if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK) {
                updateStatus(result.code.wireName)
                return@launch
            }
            if (!draft.complete(attempt)) return@launch
            closeDialog()
            updateStatus(statusMessage)
        }
    }

    fun saveDns() {
        // Capture the clicked draft before launch; the typed owner owns the command lifetime.
        val token = dnsDraft.capture()
        val plan = MainDraftLogic.resolveDnsSave(controller.currentState()).getOrNull()
        if (plan == null) {
            launch {
                if (dnsDraft.isCurrent(token)) updateStatus(SettingsStatusMessages.customDnsEndpointInvalid())
            }
            return
        }
        val attempt = try {
            dnsDraft.prepareSave(plan.settings)
        } catch (_: OutOfMemoryError) {
            launch { if (dnsDraft.isCurrent(token)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName) }
            return
        } catch (_: Exception) {
            launch { if (dnsDraft.isCurrent(token)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN.wireName) }
            return
        }
        launch {
            if (!dnsDraft.isCurrent(attempt)) return@launch
            val result = try {
                dnsDraft.save(attempt)
            } catch (_: OutOfMemoryError) {
                if (dnsDraft.isCurrent(attempt)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE.wireName)
                return@launch
            } catch (_: Exception) {
                // Explicit retry retains the request; stale frontend completions never clear a newer draft.
                if (dnsDraft.isCurrent(attempt)) updateStatus(com.kardinal.vpncontrol.model.ControlCode.OUTCOME_UNKNOWN.wireName)
                return@launch
            }
            if (!dnsDraft.isCurrent(attempt)) return@launch
            if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK) {
                updateStatus(result.code.wireName)
                return@launch
            }
            if (!dnsDraft.complete(attempt)) return@launch
            controller.update { it.copy(showDnsDialog = false) }
            updateStatus(plan.statusMessage)
        }
    }

    fun postStatus(message: String) {
        launch { updateStatus(message) }
    }
}
