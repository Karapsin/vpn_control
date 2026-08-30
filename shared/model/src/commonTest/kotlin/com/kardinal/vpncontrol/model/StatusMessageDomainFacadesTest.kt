package com.kardinal.vpncontrol.model

import kotlin.test.Test
import kotlin.test.assertEquals

class StatusMessageDomainFacadesTest {
    @Test
    fun generalDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = GeneralStatusMessages.languageSet("Deutsch"),
            key = StatusMessageKey.LANGUAGE_SET,
            args = listOf("Deutsch"),
        )
    }

    @Test
    fun runtimeDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = RuntimeStatusMessages.runtimeMode("VPN"),
            key = StatusMessageKey.RUNTIME_MODE,
            args = listOf("VPN"),
        )
        assertStructured(
            message = RuntimeStatusMessages.preflightFailed(AppMode.VPN, failedChecks = 2),
            key = StatusMessageKey.PREFLIGHT_FAILED,
            args = listOf(AppMode.VPN.name, "2"),
        )
    }

    @Test
    fun connectionDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
            key = StatusMessageKey.CONNECTION_STARTED_ON_TARGET,
            args = listOf(AppMode.VPN.name, "Germany"),
        )
        assertStructured(
            message = ConnectionStatusMessages.previousConnectionRestoreOrStopFailed(
                AppMode.PROXY_ONLY,
                restoreFailure = "restore",
                stopFailure = "stop",
            ),
            key = StatusMessageKey.PREVIOUS_CONNECTION_RESTORE_OR_STOP_FAILED,
            args = listOf(AppMode.PROXY_ONLY.name, "restore", "stop"),
        )
    }

    @Test
    fun subscriptionDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = SubscriptionStatusMessages.subscriptionRefreshStart(targetCount = 3, auto = true),
            key = StatusMessageKey.AUTO_REFRESHING_SUBSCRIPTIONS,
        )
        assertStructured(
            message = SubscriptionStatusMessages.backgroundRefreshSwitched(
                AppMode.VPN,
                selectedProfileName = "Netherlands",
                winnerSource = "Sub A",
                failedLabel = "Sub B",
            ),
            key = StatusMessageKey.BACKGROUND_REFRESH_SWITCHED_PARTIAL_SOURCE,
            args = listOf(AppMode.VPN.name, "Netherlands", "Sub A", "Sub B"),
        )
    }

    @Test
    fun benchmarkDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = BenchmarkStatusMessages.retryingBestLocationSearch(attempt = 2, total = 4),
            key = StatusMessageKey.RETRYING_BEST_LOCATION_SEARCH,
            args = listOf("2", "4"),
        )
        assertStructured(
            message = BenchmarkStatusMessages.testingLocationsRange(start = 1, end = 5, total = 20),
            key = StatusMessageKey.TESTING_LOCATIONS_RANGE,
            args = listOf("1", "5", "20"),
        )
    }

    @Test
    fun locationDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = LocationStatusMessages.locationAdded("Germany"),
            key = StatusMessageKey.LOCATION_ADDED,
            args = listOf("Germany"),
        )
        assertStructured(
            message = LocationStatusMessages.locationsExportedTo("/tmp/locations.txt"),
            key = StatusMessageKey.LOCATIONS_EXPORTED_TO,
            args = listOf("/tmp/locations.txt"),
        )
        assertStructured(
            message = LocationStatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
            key = StatusMessageKey.LOCATIONS_IMPORTED_SELECTED_UNAVAILABLE_CONNECTION_STOPPED,
            args = listOf(AppMode.VPN.name),
        )
    }

    @Test
    fun routingDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = RoutingStatusMessages.routingRulesSavedRestartRequired(AppMode.PROXY_ONLY),
            key = StatusMessageKey.ROUTING_RULES_SAVED_RESTART_REQUIRED,
            args = listOf(AppMode.PROXY_ONLY.name),
        )
        assertStructured(
            message = RoutingStatusMessages.routingRulesExportedTo("/tmp/rules.json"),
            key = StatusMessageKey.ROUTING_RULES_EXPORTED_TO,
            args = listOf("/tmp/rules.json"),
        )
    }

    @Test
    fun diagnosticsDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = DiagnosticsStatusMessages.diagnosticsExportedTo("/tmp/diagnostics.txt"),
            key = StatusMessageKey.DIAGNOSTICS_EXPORTED_TO,
            args = listOf("/tmp/diagnostics.txt"),
        )
        assertStructured(
            message = DiagnosticsStatusMessages.appsLoadFailed(),
            key = StatusMessageKey.APPS_LOAD_FAILED,
        )
    }

    @Test
    fun settingsDomainEncodesExpectedKeysAndArgs() {
        assertStructured(
            message = SettingsStatusMessages.customDnsSaved(enabled = true),
            key = StatusMessageKey.CUSTOM_DNS_SAVED,
        )
        assertStructured(
            message = SettingsStatusMessages.dnsSettingsSaved(DnsMode.AUTOMATIC),
            key = StatusMessageKey.SECURE_DNS_AUTOMATIC_SAVED,
        )
        assertStructured(
            message = SettingsStatusMessages.customDnsEndpointInvalid(),
            key = StatusMessageKey.CUSTOM_DNS_ENDPOINT_INVALID,
        )
        assertStructured(
            message = SettingsStatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY),
            key = StatusMessageKey.CONNECTION_STOPPED_FOR_APP_MODE,
            args = listOf(AppMode.VPN.name, AppMode.PROXY_ONLY.name),
        )
    }

    private fun assertStructured(
        message: String,
        key: StatusMessageKey,
        args: List<String> = emptyList(),
    ) {
        val decoded = StatusMessageCodec.decode(message)
        assertEquals(key, decoded?.key)
        assertEquals(args, decoded?.args)
    }
}
