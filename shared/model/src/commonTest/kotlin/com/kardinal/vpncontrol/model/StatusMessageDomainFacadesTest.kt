package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class StatusMessageDomainFacadesTest {
    @Test
    fun generalDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.languageSet("Deutsch"),
            GeneralStatusMessages.languageSet("Deutsch"),
        )
    }

    @Test
    fun runtimeDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.runtimeMode("VPN"),
            RuntimeStatusMessages.runtimeMode("VPN"),
        )
        assertEquals(
            StatusMessages.preflightFailed(AppMode.VPN, failedChecks = 2),
            RuntimeStatusMessages.preflightFailed(AppMode.VPN, failedChecks = 2),
        )
    }

    @Test
    fun connectionDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
        )
        assertEquals(
            StatusMessages.previousConnectionRestoreOrStopFailed(AppMode.PROXY_ONLY, "restore", "stop"),
            ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(AppMode.PROXY_ONLY, "restore", "stop"),
        )
    }

    @Test
    fun subscriptionDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.subscriptionRefreshStart(targetCount = 3, auto = true),
            SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 3, auto = true),
        )
        assertEquals(
            StatusMessages.backgroundRefreshSwitched(AppMode.VPN, "Netherlands", "Sub A", "Sub B"),
            SubscriptionStatusMessages.backgroundRefreshSwitched(AppMode.VPN, "Netherlands", "Sub A", "Sub B"),
        )
    }

    @Test
    fun benchmarkDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.retryingBestLocationSearch(attempt = 2, total = 4),
            BenchmarkStatusMessages.retryingBestLocationSearch(attempt = 2, total = 4),
        )
        assertEquals(
            StatusMessages.testingLocationsRange(start = 1, end = 5, total = 20),
            BenchmarkStatusMessages.testingLocationsRange(start = 1, end = 5, total = 20),
        )
    }

    @Test
    fun locationDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.locationAdded("Germany"),
            LocationStatusMessages.locationAdded("Germany"),
        )
        assertEquals(
            StatusMessages.locationsExportedTo("/tmp/locations.txt"),
            LocationStatusMessages.locationsExportedTo("/tmp/locations.txt"),
        )
        assertEquals(
            StatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
            LocationStatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
        )
    }

    @Test
    fun routingDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.routingRulesSavedRestartRequired(AppMode.PROXY_ONLY),
            RoutingStatusMessages.routingRulesSavedRestartRequired(AppMode.PROXY_ONLY),
        )
        assertEquals(
            StatusMessages.routingRulesExportedTo("/tmp/rules.json"),
            RoutingStatusMessages.routingRulesExportedTo("/tmp/rules.json"),
        )
    }

    @Test
    fun diagnosticsDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.diagnosticsExportedTo("/tmp/diagnostics.txt"),
            DiagnosticsStatusMessages.diagnosticsExportedTo("/tmp/diagnostics.txt"),
        )
        assertEquals(
            StatusMessages.appsLoadFailed(),
            DiagnosticsStatusMessages.appsLoadFailed(),
        )
    }

    @Test
    fun settingsDomainMatchesCompatibilityFacade() {
        assertEquals(
            StatusMessages.customDnsSaved(enabled = true),
            SettingsStatusMessages.customDnsSaved(enabled = true),
        )
        assertEquals(
            StatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY),
            SettingsStatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY),
        )
    }
}
