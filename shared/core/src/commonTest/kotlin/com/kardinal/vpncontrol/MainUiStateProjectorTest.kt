package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals

class MainUiStateProjectorTest {
    @Test
    fun mergePersistedStateProjectsSharedWorkspaceFields() {
        val subscription = SubscriptionSource(
            id = "sub-1",
            url = "https://example.com/sub",
            customName = "Example",
        )
        val persisted = PersistedState(
            appLanguage = AppLanguage.GERMAN,
            subscriptionHwid = "stable-device-hwid",
            profileUrl = subscription.url,
            activeSubscriptionId = subscription.id,
            subscriptions = listOf(subscription),
            profileHistory = listOf(subscription.url),
            profileHistoryNames = mapOf(subscription.url to "Example"),
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            appMode = AppMode.PROXY_ONLY,
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
            findBestAfterSubscriptionRefresh = false,
            subscriptionRefreshCustomHours = 0.5,
            validationSettings = BenchmarkValidationSettings(
                primaryUrl = "https://primary.example.com",
                secondaryUrl = "https://secondary.example.com",
                batchSize = 4,
                subscriptionRefreshConcurrency = 5,
                retryCount = 2,
                activeVerificationWindowSize = 6,
            ),
            currentLocations = listOf("vless://one"),
            locationBenchmarkDetails = mapOf("vless://one" to "primary ok"),
            customDns = "9.9.9.9",
            useCustomDns = true,
            routingRules = RoutingRules(
                ignoreRules = true,
                proxyPackages = listOf("app.one"),
                directDomainSuffixes = listOf("example.com"),
            ),
            selectedProfileName = "Netherlands",
            selectedProfileServer = "nl.example.com",
            selectedProfileRawLink = "vless://selected",
            selectedProfileSourceUrl = subscription.url,
            lastBenchmarkSummary = "Best: Netherlands",
            statusMessage = "Ready",
            isVpnRunning = true,
            sessionStatsEnabled = true,
            connectionLog = listOf(ConnectionLogEntry(id = "log-1", message = "Ready")),
        )

        val projected = MainUiStateProjector.mergePersistedState(MainUiState(), persisted)

        assertEquals(AppLanguage.GERMAN, projected.appLanguage)
        assertEquals("stable-device-hwid", projected.subscriptionHwid)
        assertEquals(subscription.url, projected.profileUrl)
        assertEquals(subscription.id, projected.activeSubscriptionId)
        assertEquals(listOf(subscription), projected.subscriptions)
        assertEquals(listOf(subscription.url), projected.profileHistory)
        assertEquals("Example", projected.profileHistoryNames[subscription.url])
        assertEquals(subscription.url, projected.profileDraft)
        assertEquals(ProfileSourceMode.CURRENT_LOCATIONS, projected.profileSourceMode)
        assertEquals(AppMode.PROXY_ONLY, projected.appMode)
        assertEquals(SubscriptionRefreshPolicy.CUSTOM, projected.subscriptionRefreshPolicy)
        assertEquals(false, projected.findBestAfterSubscriptionRefresh)
        assertEquals("0.5", projected.subscriptionRefreshCustomHoursDraft)
        assertEquals("https://primary.example.com", projected.validationPrimaryUrlDraft)
        assertEquals("https://secondary.example.com", projected.validationSecondaryUrlDraft)
        assertEquals("4", projected.validationBatchSizeDraft)
        assertEquals("5", projected.validationSubscriptionRefreshConcurrencyDraft)
        assertEquals("2", projected.validationRetryCountDraft)
        assertEquals("6", projected.validationActiveVerificationWindowSizeDraft)
        assertEquals(listOf("vless://one"), projected.currentLocations)
        assertEquals("primary ok", projected.locationBenchmarkDetails["vless://one"])
        assertEquals("9.9.9.9", projected.customDns)
        assertEquals("9.9.9.9", projected.customDnsDraft)
        assertEquals(true, projected.useCustomDns)
        assertEquals(true, projected.useCustomDnsDraft)
        assertEquals(true, projected.routingRules.ignoreRules)
        assertEquals(true, projected.routingIgnoreRulesDraft)
        assertEquals(setOf("app.one"), projected.routingProxyPackagesDraft)
        assertEquals("example.com", projected.routingDirectDomainsDraft)
        assertEquals("Netherlands", projected.selectedProfileName)
        assertEquals("nl.example.com", projected.selectedProfileServer)
        assertEquals("vless://selected", projected.selectedProfileRawLink)
        assertEquals(subscription.url, projected.selectedProfileSourceUrl)
        assertEquals("Best: Netherlands", projected.lastBenchmarkSummary)
        assertEquals("Ready", projected.statusMessage)
        assertEquals(true, projected.isVpnRunning)
        assertEquals(true, projected.sessionStatsEnabled)
        assertEquals("Ready", projected.connectionLog.single().message)
    }

    @Test
    fun mergePersistedStateCompactsRepeatedBestSourceSummaryForDisplay() {
        val persisted = PersistedState(
            lastBenchmarkSummary = "primary=ok secondary=ok tcp=30.9ms • Best from: One • Best from: One",
        )

        val projected = MainUiStateProjector.mergePersistedState(MainUiState(), persisted)

        assertEquals("primary=ok secondary=ok tcp=30.9ms • Best from: One", projected.lastBenchmarkSummary)
    }

    @Test
    fun mergePersistedStatePreservesOpenDrafts() {
        val current = MainUiState(
            currentScreen = AppScreen.PROFILE,
            profileDraft = "unsaved profile draft",
            showRefreshPolicyDialog = true,
            subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.CUSTOM,
            findBestAfterSubscriptionRefreshDraft = false,
            subscriptionRefreshCustomHoursDraft = "0.25",
            showValidationSettingsDialog = true,
            validationPrimaryUrlDraft = "https://draft-primary.example.com",
            validationSecondaryUrlDraft = "https://draft-secondary.example.com",
            validationBatchSizeDraft = "9",
            validationSubscriptionRefreshConcurrencyDraft = "6",
            validationRetryCountDraft = "3",
            validationActiveVerificationWindowSizeDraft = "7",
            showDnsDialog = true,
            customDnsDraft = "4.4.4.4",
            useCustomDnsDraft = true,
        )
        val persisted = PersistedState(
            profileUrl = "https://persisted.example.com/sub",
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.EVERY_HOUR,
            findBestAfterSubscriptionRefresh = true,
            subscriptionRefreshCustomHours = 2.0,
            validationSettings = BenchmarkValidationSettings(
                primaryUrl = "https://persisted-primary.example.com",
                secondaryUrl = "https://persisted-secondary.example.com",
                batchSize = 2,
                subscriptionRefreshConcurrency = 4,
                retryCount = 1,
                activeVerificationWindowSize = 2,
            ),
            customDns = "1.1.1.1",
            useCustomDns = false,
        )

        val projected = MainUiStateProjector.mergePersistedState(current, persisted)

        assertEquals("unsaved profile draft", projected.profileDraft)
        assertEquals(SubscriptionRefreshPolicy.EVERY_HOUR, projected.subscriptionRefreshPolicy)
        assertEquals(SubscriptionRefreshPolicy.CUSTOM, projected.subscriptionRefreshPolicyDraft)
        assertEquals(false, projected.findBestAfterSubscriptionRefreshDraft)
        assertEquals("0.25", projected.subscriptionRefreshCustomHoursDraft)
        assertEquals("https://draft-primary.example.com", projected.validationPrimaryUrlDraft)
        assertEquals("https://draft-secondary.example.com", projected.validationSecondaryUrlDraft)
        assertEquals("9", projected.validationBatchSizeDraft)
        assertEquals("6", projected.validationSubscriptionRefreshConcurrencyDraft)
        assertEquals("3", projected.validationRetryCountDraft)
        assertEquals("7", projected.validationActiveVerificationWindowSizeDraft)
        assertEquals("1.1.1.1", projected.customDns)
        assertEquals("4.4.4.4", projected.customDnsDraft)
        assertEquals(false, projected.useCustomDns)
        assertEquals(true, projected.useCustomDnsDraft)
    }
}
