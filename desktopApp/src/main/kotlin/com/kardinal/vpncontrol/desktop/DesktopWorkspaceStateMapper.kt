package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateProjector
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations

internal fun defaultDesktopWorkspace(): DesktopWorkspace {
    val appMode = defaultDesktopAppMode()
    val persisted = PersistedState(
        appMode = appMode,
        routingRules = RoutingRules(),
        statusMessage = ConnectionStatusMessages.connectionReadyOnComputer(appMode),
    )
    return DesktopWorkspace(
        persistedState = persisted,
        locations = emptyList(),
    )
}

internal fun restoreDesktopUiState(
    persistedState: PersistedState,
    locations: List<DesktopLocationRecord>,
): MainUiState {
    val base = MainUiStateProjector.mergePersistedState(
        current = MainUiState(
            currentScreen = AppScreen.MAIN,
            installedApps = emptyList(),
            installedAppsLoaded = true,
            hasVpnPermission = true,
        ),
        persisted = persistedState,
    )
    return syncDesktopUiStateWithLocations(
        state = base.copy(
            subscriptionRefreshPolicyDraft = persistedState.subscriptionRefreshPolicy,
            findBestAfterSubscriptionRefreshDraft = persistedState.findBestAfterSubscriptionRefresh,
            subscriptionRefreshCustomHoursDraft = persistedState.subscriptionRefreshCustomHours.toString(),
            installedApps = emptyList(),
            installedAppsLoaded = true,
            installedAppsLoading = false,
            hasVpnPermission = true,
            routingIgnoreRulesDraft = persistedState.routingRules.ignoreRules,
            routingProxyPackagesDraft = persistedState.routingRules.proxyPackages.toSet(),
            routingDirectDomainsDraft = persistedState.routingRules.directDomainSuffixes.joinToString("\n"),
            routingRuleSetsDraft = emptyList(),
        ),
        locations = locations,
    )
}

internal fun BenchmarkValidationSettings.toDesktopValidationSettings(): DesktopValidationSettings {
    val normalized = normalized()
    val concurrency = minOf(normalized.subscriptionRefreshConcurrency.coerceAtLeast(1), 5)
    return DesktopValidationSettings(
        preflightConcurrency = concurrency,
        batchSize = normalized.batchSize,
    )
}

internal fun syncDesktopUiStateWithLocations(
    state: MainUiState,
    locations: List<DesktopLocationRecord>,
): MainUiState {
    val syncedSubscriptions = syncSubscriptionsWithLocations(state.subscriptions, locations)
    val savedLocations = locations.filter { it.sourceUrl.isBlank() }
    val effectiveActiveSubscriptionId = when {
        isAllSubscriptionsGroupActive(state.activeSubscriptionId, syncedSubscriptions) -> ALL_SUBSCRIPTIONS_ID
        state.activeSubscriptionId.isBlank() -> syncedSubscriptions.firstOrNull()?.id.orEmpty()
        syncedSubscriptions.none { it.id == state.activeSubscriptionId } -> syncedSubscriptions.firstOrNull()?.id.orEmpty()
        else -> state.activeSubscriptionId
    }
    val visibleCurrentLocations = when (state.profileSourceMode) {
        ProfileSourceMode.SUBSCRIPTION -> when {
            isAllSubscriptionsGroupActive(effectiveActiveSubscriptionId, syncedSubscriptions) ->
                mergedSubscriptionLocations(syncedSubscriptions)
            else ->
                syncedSubscriptions.firstOrNull { it.id == effectiveActiveSubscriptionId }
                    ?.cachedLocations
                    .orEmpty()
        }
        ProfileSourceMode.CURRENT_LOCATIONS -> savedLocations.map(DesktopLocationRecord::rawLink)
    }
    val selectedLocation = locations.firstOrNull { it.matchesSelectedLocation(state) }
    return state.copy(
        subscriptions = syncedSubscriptions,
        activeSubscriptionId = effectiveActiveSubscriptionId,
        profileUrl = when {
            isAllSubscriptionsGroupActive(effectiveActiveSubscriptionId, syncedSubscriptions) -> ""
            else -> syncedSubscriptions.firstOrNull { it.id == effectiveActiveSubscriptionId }?.url.orEmpty()
        },
        profileHistory = syncedSubscriptions.map(SubscriptionSource::url),
        profileHistoryNames = syncedSubscriptions
            .filter { it.customName.isNotBlank() }
            .associate { it.url to it.customName },
        currentLocations = visibleCurrentLocations,
        locationBenchmarkDetails = locations.associate { it.rawLink to it.benchmarkDetail },
        selectedProfileName = selectedLocation?.name ?: state.selectedProfileName.takeIf { it.isNotBlank() }.orEmpty(),
        selectedProfileServer = selectedLocation?.server ?: state.selectedProfileServer.takeIf { it.isNotBlank() }.orEmpty(),
        selectedProfileRawLink = selectedLocation?.rawLink ?: state.selectedProfileRawLink.takeIf { raw ->
            raw.isNotBlank() && locations.any { it.rawLink == raw }
        }.orEmpty(),
        selectedProfileSourceUrl = selectedLocation?.sourceUrl ?: state.selectedProfileSourceUrl.takeIf { url ->
            url.isNotBlank() && locations.any { it.sourceUrl == url }
        }.orEmpty(),
    )
}

internal fun syncDesktopLocationsWithSelection(
    state: MainUiState,
    locations: List<DesktopLocationRecord>,
): List<DesktopLocationRecord> {
    var selectedApplied = false
    return locations.map { location ->
        val isSelected = !selectedApplied && location.matchesSelectedLocation(state)
        if (isSelected) {
            selectedApplied = true
        }
        if (location.isSelected == isSelected) {
            location
        } else {
            location.copy(isSelected = isSelected)
        }
    }
}

internal fun syncSubscriptionsWithLocations(
    subscriptions: List<SubscriptionSource>,
    locations: List<DesktopLocationRecord>,
): List<SubscriptionSource> {
    val groupedLocations = locations
        .filter { it.sourceUrl.isNotBlank() }
        .groupBy(DesktopLocationRecord::sourceUrl)
        .mapValues { (_, values) -> values.map(DesktopLocationRecord::rawLink) }
    return subscriptions.map { subscription ->
        subscription.copy(cachedLocations = groupedLocations[subscription.url].orEmpty())
    }
}

internal fun MainUiState.toPersistedState(
    locations: List<DesktopLocationRecord>,
): PersistedState {
    val synced = syncDesktopUiStateWithLocations(this, locations)
    val routingRules = RoutingRules(
        ignoreRules = synced.routingIgnoreRulesDraft,
        blockQuicUdp443 = synced.routingBlockQuicUdp443Draft,
        proxyPackages = RoutingRules.normalizePackageNames(synced.routingProxyPackagesDraft),
        bypassPackages = emptyList(),
        directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(synced.routingDirectDomainsDraft),
        ruleSets = emptyList(),
    )
    return PersistedState(
        appLanguage = synced.appLanguage,
        subscriptionHwid = synced.subscriptionHwid,
        profileUrl = synced.profileUrl,
        activeSubscriptionId = synced.activeSubscriptionId,
        subscriptions = synced.subscriptions,
        profileHistory = synced.profileHistory,
        profileHistoryNames = synced.profileHistoryNames,
        profileSourceMode = synced.profileSourceMode,
        appMode = synced.appMode,
        subscriptionRefreshPolicy = synced.subscriptionRefreshPolicy,
        findBestAfterSubscriptionRefresh = synced.findBestAfterSubscriptionRefresh,
        subscriptionRefreshCustomHours = synced.subscriptionRefreshCustomHours,
        validationSettings = synced.validationSettings,
        savedLocations = locations.filter { it.sourceUrl.isBlank() }.map(DesktopLocationRecord::rawLink),
        currentLocations = synced.currentLocations,
        locationBenchmarkDetails = synced.locationBenchmarkDetails,
        dnsSettings = synced.dnsSettings,
        routingRules = routingRules,
        selectedProfileName = synced.selectedProfileName,
        selectedProfileServer = synced.selectedProfileServer,
        selectedProfileRawLink = synced.selectedProfileRawLink,
        selectedProfileJson = synced.selectedProfileJson,
        selectedProfileSourceUrl = synced.selectedProfileSourceUrl,
        lastBenchmarkSummary = synced.lastBenchmarkSummary,
        runtimeConfigJson = "",
        statusMessage = synced.statusMessage,
        isVpnRunning = synced.isVpnRunning,
        sessionStatsEnabled = synced.sessionStatsEnabled,
        liveTrafficStatsEnabled = synced.liveTrafficStatsEnabled,
        profileTotalsEnabled = synced.profileTotalsEnabled,
        latencyHistoryEnabled = synced.latencyHistoryEnabled,
        connectionLogEnabled = synced.connectionLogEnabled,
        connectionTestToolsEnabled = synced.connectionTestToolsEnabled,
        sessionStartedAtEpochMillis = synced.sessionStartedAtEpochMillis,
        sessionStoppedAtEpochMillis = synced.sessionStoppedAtEpochMillis,
        sessionStartRxBytes = synced.sessionStartRxBytes,
        sessionStartTxBytes = synced.sessionStartTxBytes,
        successfulStarts = synced.successfulStarts,
        successfulStops = synced.successfulStops,
        profileTrafficTotals = synced.profileTrafficTotals,
        latencyHistory = synced.latencyHistory,
        connectionLog = synced.connectionLog,
    )
}

internal fun String.toCompactBenchmarkLabel(): String {
    val test = Regex("""test=([a-z]+)""").find(this)?.groupValues?.getOrNull(1)
    val primary = Regex("""primary=([a-z]+)""").find(this)?.groupValues?.getOrNull(1)
    val secondary = Regex("""secondary=([a-z]+)""").find(this)?.groupValues?.getOrNull(1)
    val tcp = Regex("""tcp=([0-9.]+ms|unreachable)""").find(this)?.groupValues?.getOrNull(1)
    return when {
        test != null && tcp != null ->
            "test $test • tcp $tcp"
        test != null ->
            "test $test"
        primary != null && secondary != null && tcp != null ->
            "primary $primary • secondary $secondary • tcp $tcp"
        primary != null && secondary != null ->
            "primary $primary • secondary $secondary"
        contains("tcp=") -> replace(':', ' ').trim()
        else -> this
    }
}

internal fun benchmarkDetailIndicatesSelectable(detail: String, previousIsValid: Boolean): Boolean {
    val test = Regex("""(?:^|\s)test[= ]([a-z]+)""").find(detail)?.groupValues?.getOrNull(1)
    if (test != null) {
        return test == "ok"
    }

    val primary = Regex("""(?:^|\s)primary[= ]([a-z]+)""").find(detail)?.groupValues?.getOrNull(1)
    if (primary != null) {
        val secondary = Regex("""(?:^|\s)secondary[= ]([a-z]+)""").find(detail)?.groupValues?.getOrNull(1)
        return primary == "ok" || (primary == "manual" && secondary == "ok")
    }

    if (detail.contains("tcp_unreachable")) {
        return false
    }

    val tcp = Regex("""(?:^|\s)tcp[= ]([0-9.]+ms|unreachable)""").find(detail)?.groupValues?.getOrNull(1)
    if (tcp != null) {
        return tcp != "unreachable"
    }

    return previousIsValid
}
