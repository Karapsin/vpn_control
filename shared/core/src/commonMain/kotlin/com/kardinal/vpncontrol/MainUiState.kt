package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.formatSubscriptionRefreshHoursInput

enum class AppScreen {
    MAIN,
    PROFILE,
    LOCATIONS,
    ROUTING_RULES,
    STATS,
}

data class MainUiState(
    val currentScreen: AppScreen = AppScreen.MAIN,
    val appLanguage: AppLanguage = AppLanguage.SYSTEM,
    val subscriptionHwid: String = "",
    val screenHistory: List<AppScreen> = emptyList(),
    val profileUrl: String = "",
    val activeSubscriptionId: String = "",
    val subscriptions: List<SubscriptionSource> = emptyList(),
    val profileHistory: List<String> = emptyList(),
    val profileHistoryNames: Map<String, String> = emptyMap(),
    val profileDraft: String = "",
    val profileTitleDraft: String = "",
    val showAddSubscriptionEditor: Boolean = false,
    val profileSourceMode: ProfileSourceMode = ProfileSourceMode.SUBSCRIPTION,
    val appMode: AppMode = AppMode.VPN,
    val subscriptionRefreshPolicy: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val subscriptionRefreshPolicyDraft: SubscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
    val findBestAfterSubscriptionRefresh: Boolean = true,
    val findBestAfterSubscriptionRefreshDraft: Boolean = true,
    val subscriptionRefreshCustomHours: Double = DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS,
    val subscriptionRefreshCustomHoursDraft: String = "3",
    val validationSettings: BenchmarkValidationSettings = BenchmarkValidationSettings(),
    val validationPrimaryUrlDraft: String = BenchmarkValidationSettings.DEFAULT_PRIMARY_URL,
    val validationSecondaryUrlDraft: String = BenchmarkValidationSettings.DEFAULT_SECONDARY_URL,
    val validationBatchSizeDraft: String = BenchmarkValidationSettings.DEFAULT_BATCH_SIZE.toString(),
    val validationSubscriptionRefreshConcurrencyDraft: String =
        BenchmarkValidationSettings.DEFAULT_SUBSCRIPTION_REFRESH_CONCURRENCY.toString(),
    val validationRetryCountDraft: String = BenchmarkValidationSettings.DEFAULT_RETRY_COUNT.toString(),
    val validationActiveVerificationWindowSizeDraft: String =
        BenchmarkValidationSettings.DEFAULT_ACTIVE_VERIFICATION_WINDOW_SIZE.toString(),
    val currentLocations: List<String> = emptyList(),
    val locationBenchmarkDetails: Map<String, String> = emptyMap(),
    val customDns: String = "",
    val customDnsDraft: String = "",
    val useCustomDns: Boolean = false,
    val useCustomDnsDraft: Boolean = false,
    val routingRules: RoutingRules = RoutingRules(),
    val routingIgnoreRulesDraft: Boolean = false,
    val routingProxyPackagesDraft: Set<String> = emptySet(),
    val routingBypassPackagesDraft: Set<String> = emptySet(),
    val routingDirectDomainsDraft: String = "",
    val routingRuleSetsDraft: List<RoutingRuleSet> = emptyList(),
    val routingAppSearch: String = "",
    val installedApps: List<InstalledApp> = emptyList(),
    val installedAppsLoaded: Boolean = false,
    val installedAppsLoading: Boolean = false,
    val isVpnRunning: Boolean = false,
    val isBusy: Boolean = false,
    val isRefreshing: Boolean = false,
    val isStartingVpn: Boolean = false,
    val selectedProfileName: String = "",
    val selectedProfileServer: String = "",
    val selectedProfileRawLink: String = "",
    val selectedProfileJson: String = "",
    val selectedProfileSourceUrl: String = "",
    val lastBenchmarkSummary: String = "",
    val statusMessage: String = "Idle",
    val sessionStatsEnabled: Boolean = false,
    val liveTrafficStatsEnabled: Boolean = false,
    val profileTotalsEnabled: Boolean = false,
    val latencyHistoryEnabled: Boolean = false,
    val connectionLogEnabled: Boolean = false,
    val connectionTestToolsEnabled: Boolean = false,
    val sessionStartedAtEpochMillis: Long = 0L,
    val sessionStoppedAtEpochMillis: Long = 0L,
    val sessionStartRxBytes: Long = -1L,
    val sessionStartTxBytes: Long = -1L,
    val successfulStarts: Int = 0,
    val successfulStops: Int = 0,
    val profileTrafficTotals: List<ProfileTrafficTotal> = emptyList(),
    val latencyHistory: List<LatencyHistoryEntry> = emptyList(),
    val connectionLog: List<ConnectionLogEntry> = emptyList(),
    val showDnsDialog: Boolean = false,
    val showUiSettingsDialog: Boolean = false,
    val showAppModeDialog: Boolean = false,
    val showRefreshPolicyDialog: Boolean = false,
    val showValidationSettingsDialog: Boolean = false,
    val showLanguageDialog: Boolean = false,
    val showProfileHistoryRenameDialog: Boolean = false,
    val showRuleSetDialog: Boolean = false,
    val editingRuleSetId: String = "",
    val routingRuleSetNameDraft: String = "",
    val routingRuleSetSourceDraft: String = "",
    val routingRuleSetSourceTypeDraft: RoutingRuleSetSourceType = RoutingRuleSetSourceType.REMOTE,
    val routingRuleSetFormatDraft: RoutingRuleSetFormat = RoutingRuleSetFormat.SOURCE,
    val routingRuleSetActionDraft: RoutingRuleSetAction = RoutingRuleSetAction.DIRECT,
    val routingRuleSetUpdateHoursDraft: String = "24",
    val profileHistoryRenameSource: String = "",
    val profileHistoryRenameUrlDraft: String = "",
    val profileHistoryRenameDraft: String = "",
    val showLocationMutationBlockedDialog: Boolean = false,
    val locationMutationBlockedMessage: String = "",
    val showLocationDialog: Boolean = false,
    val locationDraft: String = "",
    val editingLocationIndex: Int? = null,
    val hasVpnPermission: Boolean = false,
    val startOnBootEnabled: Boolean = false,
)

object MainUiStateProjector {
    fun mergePersistedState(
        current: MainUiState,
        persisted: PersistedState,
    ): MainUiState {
        return current.copy(
            appLanguage = persisted.appLanguage,
            subscriptionHwid = persisted.subscriptionHwid,
            profileUrl = persisted.profileUrl,
            activeSubscriptionId = persisted.activeSubscriptionId,
            subscriptions = persisted.subscriptions,
            profileHistory = persisted.profileHistory,
            profileHistoryNames = persisted.profileHistoryNames,
            profileDraft = if (current.currentScreen == AppScreen.PROFILE) {
                current.profileDraft
            } else {
                persisted.profileUrl
            },
            profileSourceMode = persisted.profileSourceMode,
            appMode = persisted.appMode,
            subscriptionRefreshPolicy = persisted.subscriptionRefreshPolicy,
            subscriptionRefreshPolicyDraft = if (current.showRefreshPolicyDialog) {
                current.subscriptionRefreshPolicyDraft
            } else {
                persisted.subscriptionRefreshPolicy
            },
            findBestAfterSubscriptionRefresh = persisted.findBestAfterSubscriptionRefresh,
            findBestAfterSubscriptionRefreshDraft = if (current.showRefreshPolicyDialog) {
                current.findBestAfterSubscriptionRefreshDraft
            } else {
                persisted.findBestAfterSubscriptionRefresh
            },
            subscriptionRefreshCustomHours = persisted.subscriptionRefreshCustomHours,
            subscriptionRefreshCustomHoursDraft = if (current.showRefreshPolicyDialog) {
                current.subscriptionRefreshCustomHoursDraft
            } else {
                formatSubscriptionRefreshHoursInput(persisted.subscriptionRefreshCustomHours)
            },
            validationSettings = persisted.validationSettings,
            validationPrimaryUrlDraft = if (current.showValidationSettingsDialog) {
                current.validationPrimaryUrlDraft
            } else {
                persisted.validationSettings.primaryUrl
            },
            validationSecondaryUrlDraft = if (current.showValidationSettingsDialog) {
                current.validationSecondaryUrlDraft
            } else {
                persisted.validationSettings.secondaryUrl
            },
            validationBatchSizeDraft = if (current.showValidationSettingsDialog) {
                current.validationBatchSizeDraft
            } else {
                persisted.validationSettings.batchSize.toString()
            },
            validationSubscriptionRefreshConcurrencyDraft = if (current.showValidationSettingsDialog) {
                current.validationSubscriptionRefreshConcurrencyDraft
            } else {
                persisted.validationSettings.subscriptionRefreshConcurrency.toString()
            },
            validationRetryCountDraft = if (current.showValidationSettingsDialog) {
                current.validationRetryCountDraft
            } else {
                persisted.validationSettings.retryCount.toString()
            },
            validationActiveVerificationWindowSizeDraft = if (current.showValidationSettingsDialog) {
                current.validationActiveVerificationWindowSizeDraft
            } else {
                persisted.validationSettings.activeVerificationWindowSize.toString()
            },
            currentLocations = persisted.currentLocations,
            locationBenchmarkDetails = persisted.locationBenchmarkDetails,
            customDns = persisted.customDns,
            customDnsDraft = if (current.showDnsDialog) current.customDnsDraft else persisted.customDns,
            useCustomDns = persisted.useCustomDns,
            useCustomDnsDraft = if (current.showDnsDialog) current.useCustomDnsDraft else persisted.useCustomDns,
            routingRules = persisted.routingRules.copy(ruleSets = emptyList()),
            routingIgnoreRulesDraft = if (current.currentScreen == AppScreen.ROUTING_RULES) {
                current.routingIgnoreRulesDraft
            } else {
                persisted.routingRules.ignoreRules
            },
            routingProxyPackagesDraft = if (current.currentScreen == AppScreen.ROUTING_RULES) {
                current.routingProxyPackagesDraft
            } else {
                persisted.routingRules.proxyPackages.toSet()
            },
            routingDirectDomainsDraft = if (current.currentScreen == AppScreen.ROUTING_RULES) {
                current.routingDirectDomainsDraft
            } else {
                persisted.routingRules.directDomainSuffixes.joinToString(separator = "\n")
            },
            routingRuleSetsDraft = emptyList(),
            selectedProfileName = persisted.selectedProfileName,
            selectedProfileServer = persisted.selectedProfileServer,
            selectedProfileRawLink = persisted.selectedProfileRawLink,
            selectedProfileJson = persisted.selectedProfileJson,
            selectedProfileSourceUrl = persisted.selectedProfileSourceUrl,
            lastBenchmarkSummary = BenchmarkSummaryFormatter.compactBestSourceRepeats(persisted.lastBenchmarkSummary),
            isVpnRunning = persisted.isVpnRunning,
            statusMessage = persisted.statusMessage,
            sessionStatsEnabled = persisted.sessionStatsEnabled,
            liveTrafficStatsEnabled = persisted.liveTrafficStatsEnabled,
            profileTotalsEnabled = persisted.profileTotalsEnabled,
            latencyHistoryEnabled = persisted.latencyHistoryEnabled,
            connectionLogEnabled = persisted.connectionLogEnabled,
            connectionTestToolsEnabled = persisted.connectionTestToolsEnabled,
            sessionStartedAtEpochMillis = persisted.sessionStartedAtEpochMillis,
            sessionStoppedAtEpochMillis = persisted.sessionStoppedAtEpochMillis,
            sessionStartRxBytes = persisted.sessionStartRxBytes,
            sessionStartTxBytes = persisted.sessionStartTxBytes,
            successfulStarts = persisted.successfulStarts,
            successfulStops = persisted.successfulStops,
            profileTrafficTotals = persisted.profileTrafficTotals,
            latencyHistory = persisted.latencyHistory,
            connectionLog = persisted.connectionLog,
        )
    }
}

object MainUiStateTransitions {
    fun toggleRefreshPolicyDialog(state: MainUiState): MainUiState {
        return state.copy(
            showRefreshPolicyDialog = !state.showRefreshPolicyDialog,
            subscriptionRefreshPolicyDraft = state.subscriptionRefreshPolicy,
            findBestAfterSubscriptionRefreshDraft = state.findBestAfterSubscriptionRefresh,
            subscriptionRefreshCustomHoursDraft = formatSubscriptionRefreshHoursInput(
                state.subscriptionRefreshCustomHours,
            ),
        )
    }

    fun toggleValidationSettingsDialog(state: MainUiState): MainUiState {
        val current = state.validationSettings
        return state.copy(
            showValidationSettingsDialog = !state.showValidationSettingsDialog,
            validationPrimaryUrlDraft = current.primaryUrl,
            validationSecondaryUrlDraft = current.secondaryUrl,
            validationBatchSizeDraft = current.batchSize.toString(),
            validationSubscriptionRefreshConcurrencyDraft = current.subscriptionRefreshConcurrency.toString(),
            validationRetryCountDraft = current.retryCount.toString(),
            validationActiveVerificationWindowSizeDraft = current.activeVerificationWindowSize.toString(),
        )
    }

    fun toggleAddSubscriptionEditor(state: MainUiState): MainUiState {
        val opening = !state.showAddSubscriptionEditor
        return state.copy(
            showAddSubscriptionEditor = opening,
            profileDraft = if (opening && state.profileDraft == state.profileUrl) {
                ""
            } else {
                state.profileDraft
            },
            profileTitleDraft = "",
        )
    }

    fun prepareRoutingRulesScreen(state: MainUiState): MainUiState {
        val rules = state.routingRules
        return state.copy(
            routingIgnoreRulesDraft = rules.ignoreRules,
            routingProxyPackagesDraft = rules.proxyPackages.toSet(),
            routingBypassPackagesDraft = emptySet(),
            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
            routingRuleSetsDraft = emptyList(),
            routingAppSearch = "",
            showRuleSetDialog = false,
        )
    }

    fun navigateBack(state: MainUiState): MainUiState {
        val history = state.screenHistory
        return when {
            history.isNotEmpty() -> {
                val target = history.last()
                state.copy(
                    currentScreen = target,
                    screenHistory = history.dropLast(1),
                    profileDraft = if (target == AppScreen.PROFILE) state.profileUrl else state.profileDraft,
                    profileTitleDraft = if (target == AppScreen.PROFILE) "" else state.profileTitleDraft,
                )
            }
            state.currentScreen != AppScreen.MAIN -> {
                state.copy(currentScreen = AppScreen.MAIN)
            }
            else -> state
        }
    }

    fun navigateToScreen(
        state: MainUiState,
        screen: AppScreen,
    ): MainUiState {
        val current = state.currentScreen
        if (current == screen) return state
        return state.copy(
            currentScreen = screen,
            screenHistory = state.screenHistory + current,
            profileDraft = if (screen == AppScreen.PROFILE) state.profileUrl else state.profileDraft,
            profileTitleDraft = if (screen == AppScreen.PROFILE) "" else state.profileTitleDraft,
            showAddSubscriptionEditor = if (screen == AppScreen.PROFILE) false else state.showAddSubscriptionEditor,
        )
    }
}
