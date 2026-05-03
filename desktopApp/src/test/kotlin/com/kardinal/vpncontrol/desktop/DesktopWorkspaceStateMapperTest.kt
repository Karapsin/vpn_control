package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopWorkspaceStateMapperTest {
    @Test
    fun defaultWorkspaceStartsEmptyWithPlatformModeStatus() {
        val workspace = defaultDesktopWorkspace()

        assertTrue(workspace.locations.isEmpty())
        assertEquals(defaultDesktopAppMode(), workspace.persistedState.appMode)
        assertEquals(
            ConnectionStatusMessages.connectionReadyOnComputer(defaultDesktopAppMode()),
            workspace.persistedState.statusMessage,
        )
        assertTrue(workspace.persistedState.subscriptions.isEmpty())
        assertTrue(workspace.persistedState.routingRules.directDomainSuffixes.isEmpty())
    }

    @Test
    fun restoreDesktopUiStateAppliesDesktopDraftsAndLocationSync() {
        val subscription = SubscriptionSource(
            id = "sub",
            url = "https://example.com/sub.txt",
            customName = "Example",
        )
        val location = location(
            index = 4,
            sourceUrl = subscription.url,
            rawLink = "socks://user:pass@127.0.0.1:1080#Selected",
            name = "Selected",
            benchmarkDetail = "primary ok",
            isSelected = true,
        )
        val restored = restoreDesktopUiState(
            persistedState = PersistedState(
                subscriptions = listOf(subscription),
                activeSubscriptionId = subscription.id,
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                subscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
                findBestAfterSubscriptionRefresh = true,
                subscriptionRefreshCustomHours = 0.5,
                routingRules = RoutingRules(
                    ignoreRules = true,
                    proxyPackages = listOf("org.example.app"),
                    nationalDomainSuffixes = listOf("ru"),
                    directDomainSuffixes = listOf("example.com"),
                ),
                selectedProfileRawLink = location.rawLink,
            ),
            locations = listOf(location),
        )

        assertEquals(AppScreen.MAIN, restored.currentScreen)
        assertTrue(restored.hasVpnPermission)
        assertTrue(restored.installedAppsLoaded)
        assertFalse(restored.installedAppsLoading)
        assertEquals(SubscriptionRefreshPolicy.CUSTOM, restored.subscriptionRefreshPolicyDraft)
        assertTrue(restored.findBestAfterSubscriptionRefreshDraft)
        assertEquals("0.5", restored.subscriptionRefreshCustomHoursDraft)
        assertTrue(restored.routingIgnoreRulesDraft)
        assertEquals(setOf("org.example.app"), restored.routingProxyPackagesDraft)
        assertEquals("ru", restored.routingNationalDomainsDraft)
        assertEquals("example.com", restored.routingDirectDomainsDraft)
        assertEquals(listOf(location.rawLink), restored.currentLocations)
        assertEquals(location.rawLink, restored.selectedProfileRawLink)
        assertEquals("Selected", restored.selectedProfileName)
        assertEquals("primary ok", restored.locationBenchmarkDetails[location.rawLink])
    }

    @Test
    fun syncDesktopUiStateWithLocationsBuildsAllSubscriptionCurrentLocations() {
        val first = SubscriptionSource(id = "one", url = "https://example.com/one")
        val second = SubscriptionSource(id = "two", url = "https://example.com/two")
        val firstLocation = location(index = 1, sourceUrl = first.url, rawLink = "socks://a#a")
        val secondLocation = location(index = 2, sourceUrl = second.url, rawLink = "socks://b#b")

        val synced = syncDesktopUiStateWithLocations(
            state = MainUiState(
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
                subscriptions = listOf(first, second),
            ),
            locations = listOf(firstLocation, secondLocation),
        )

        assertEquals(ALL_SUBSCRIPTIONS_ID, synced.activeSubscriptionId)
        assertEquals("", synced.profileUrl)
        assertEquals(listOf(first.url, second.url), synced.profileHistory)
        assertEquals(listOf(firstLocation.rawLink, secondLocation.rawLink), synced.currentLocations)
        assertEquals(listOf(firstLocation.rawLink), synced.subscriptions[0].cachedLocations)
        assertEquals(listOf(secondLocation.rawLink), synced.subscriptions[1].cachedLocations)
    }

    @Test
    fun toPersistedStateStoresSavedLocationsAndNormalizedRoutingDrafts() {
        val saved = location(index = 0, sourceUrl = "", rawLink = "socks://saved#saved")
        val remote = location(index = 1, sourceUrl = "https://example.com/sub", rawLink = "socks://remote#remote")
        val persisted = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            routingIgnoreRulesDraft = false,
            routingProxyPackagesDraft = setOf("  org.example.app  ", ""),
            routingNationalDomainsDraft = "ru\n by ",
            routingDirectDomainsDraft = "example.com\n",
        ).toPersistedState(listOf(saved, remote))

        assertEquals(listOf(saved.rawLink), persisted.savedLocations)
        assertEquals(listOf(saved.rawLink), persisted.currentLocations)
        assertEquals(listOf("org.example.app"), persisted.routingRules.proxyPackages)
        assertEquals(listOf("ru", "by"), persisted.routingRules.nationalDomainSuffixes)
        assertEquals(listOf("example.com"), persisted.routingRules.directDomainSuffixes)
        assertEquals("", persisted.runtimeConfigJson)
    }

    @Test
    fun benchmarkDetailSelectableRulesCoverCompactAndRawDetails() {
        assertTrue(benchmarkDetailIndicatesSelectable("Example: tcp=80.0ms", previousIsValid = false))
        assertFalse(benchmarkDetailIndicatesSelectable("Example: tcp=unreachable", previousIsValid = true))
        assertTrue(
            benchmarkDetailIndicatesSelectable(
                "Example: tcp=39.4ms primary=ok primary_codes=204 secondary=ok secondary_codes=200",
                previousIsValid = false,
            ),
        )
        assertFalse(
            benchmarkDetailIndicatesSelectable(
                "primary bad - secondary bad - tcp 46.4ms",
                previousIsValid = true,
            ),
        )
    }
}

private fun location(
    index: Int,
    sourceUrl: String,
    rawLink: String,
    name: String = "Location",
    benchmarkDetail: String = "Imported",
    isSelected: Boolean = false,
): DesktopLocationRecord {
    return DesktopLocationRecord(
        index = index,
        sourceUrl = sourceUrl,
        rawLink = rawLink,
        name = name,
        server = "127.0.0.$index",
        details = "SOCKS",
        benchmarkDetail = benchmarkDetail,
        isValid = true,
        isSelected = isSelected,
    )
}
