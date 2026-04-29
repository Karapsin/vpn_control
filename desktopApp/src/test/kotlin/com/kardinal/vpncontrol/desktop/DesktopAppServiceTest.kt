package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.nio.file.Files
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopAppServiceTest {
    @Test
    fun workspaceWriteSurvivesNonFiniteMetrics() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-non-finite")
        try {
            val store = DesktopStateStore(tempDir)
            store.writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(
                        subscriptionRefreshCustomHours = Double.POSITIVE_INFINITY,
                        latencyHistory = listOf(
                            LatencyHistoryEntry(
                                id = "bad-metric",
                                profileName = "Example",
                                detail = "failed",
                                primaryStatus = "error",
                                secondaryStatus = "error",
                                primaryTotalMs = Double.POSITIVE_INFINITY,
                                secondaryTotalMs = Double.NaN,
                            ),
                        ),
                    ),
                    locations = emptyList(),
                ),
            )

            val workspaceFile = tempDir.resolve("workspace.json")
            val raw = Files.readString(workspaceFile)
            val loaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )

            assertTrue(Files.exists(workspaceFile))
            assertFalse(raw.contains("Infinity"))
            assertFalse(raw.contains("NaN"))
            assertFalse(Files.exists(tempDir.resolve("workspace-write-error.log")))
            assertEquals(
                DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS,
                loaded.persistedState.subscriptionRefreshCustomHours,
            )
            assertEquals(null, loaded.persistedState.latencyHistory.single().primaryTotalMs)
            assertEquals(null, loaded.persistedState.latencyHistory.single().secondaryTotalMs)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun workspaceWriteFallsBackToRecoveryWhenPrimaryCannotBeReplaced() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-recovery-write")
        try {
            Files.createDirectories(tempDir.resolve("workspace.json"))
            val store = DesktopStateStore(tempDir)

            store.writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(profileUrl = "https://example.com/recovered"),
                    locations = emptyList(),
                ),
            )

            assertTrue(Files.exists(tempDir.resolve("workspace-recovery.json")))
            assertFalse(Files.exists(tempDir.resolve("workspace-write-error.log")))

            val loaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )
            assertEquals("https://example.com/recovered", loaded.persistedState.profileUrl)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun loadWorkspacePrefersNewerRecoveryWorkspace() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-recovery-load")
        val recoveryDir = Files.createTempDirectory("vpn-control-desktop-recovery-source")
        try {
            val store = DesktopStateStore(tempDir)
            store.writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(profileUrl = "https://example.com/stale"),
                    locations = emptyList(),
                ),
            )
            DesktopStateStore(recoveryDir).writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(profileUrl = "https://example.com/fresh"),
                    locations = emptyList(),
                ),
            )
            val primary = tempDir.resolve("workspace.json")
            val recovery = tempDir.resolve("workspace-recovery.json")
            Files.copy(recoveryDir.resolve("workspace.json"), recovery)
            Files.setLastModifiedTime(primary, FileTime.fromMillis(1_000L))
            Files.setLastModifiedTime(recovery, FileTime.fromMillis(2_000L))

            val loaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )

            assertEquals("https://example.com/fresh", loaded.persistedState.profileUrl)
        } finally {
            tempDir.toFile().deleteRecursively()
            recoveryDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun defaultWorkspaceUsesPlatformDefaultModeWithoutDefaultRoutingDomains() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-defaults")
        try {
            val service = DesktopAppService.createForTesting(store = DesktopStateStore(tempDir))

            assertEquals(defaultDesktopAppMode(), service.state.appMode)
            assertTrue(service.state.routingRules.nationalDomainSuffixes.isEmpty())
            assertTrue(service.state.routingRules.directDomainSuffixes.isEmpty())
            assertTrue(service.state.routingNationalDomainsDraft.isBlank())
            assertTrue(service.state.routingDirectDomainsDraft.isBlank())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun selectedAppLanguagePersistsAcrossRestart() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-language")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)

            service.setAppLanguage(AppLanguage.RUSSIAN)

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )
            assertEquals(AppLanguage.RUSSIAN, reloaded.persistedState.appLanguage)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun legacyDefaultWorkspaceMigratesToVpnModeAndEmptyRoutingDomains() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-legacy-defaults")
        try {
            val store = DesktopStateStore(tempDir)
            val subscriptions = listOf(
                SubscriptionSource(id = "desktop-sub-1", url = "https://desktop.example.net/whitelists"),
                SubscriptionSource(id = "desktop-sub-2", url = "https://desktop.example.net/fallback"),
            )
            store.writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(
                        profileUrl = subscriptions.first().url,
                        activeSubscriptionId = subscriptions.first().id,
                        subscriptions = subscriptions,
                        profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                        appMode = AppMode.PROXY_ONLY,
                        routingRules = RoutingRules(
                            proxyPackages = listOf("com.example.browser", "org.telegram.messenger"),
                            nationalDomainSuffixes = listOf("ru", "by"),
                            directDomainSuffixes = listOf("example.com", "intranet.local"),
                        ),
                        selectedProfileRawLink = "vless://desktop-nl",
                        statusMessage = "Desktop proxy shell ready",
                        connectionLog = listOf(ConnectionLogEntry(id = "legacy", message = "Proxy mode available")),
                    ),
                    locations = emptyList(),
                ),
            )

            val migrated = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            ).persistedState

            assertEquals(AppMode.VPN, migrated.appMode)
            assertTrue(migrated.routingRules.nationalDomainSuffixes.isEmpty())
            assertTrue(migrated.routingRules.directDomainSuffixes.isEmpty())
            assertTrue(migrated.routingRules.proxyPackages.isEmpty())
            assertEquals("Desktop VPN shell ready", migrated.statusMessage)
            assertEquals("VPN mode available", migrated.connectionLog.single().message)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun loadWorkspaceRepairsPreflightReachableLocationsMarkedInvalid() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-location-validity")
        try {
            val store = DesktopStateStore(tempDir)
            store.writeWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = listOf(
                        DesktopLocationRecord(
                            index = 1,
                            sourceUrl = "https://example.com/subscription.txt",
                            rawLink = "vless://example",
                            name = "Example",
                            server = "example.com",
                            details = "VLESS REALITY",
                            benchmarkDetail = "Example: tcp=80.0ms",
                            isValid = false,
                        ),
                    ),
                ),
            )

            val loaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(persistedState = PersistedState(), locations = emptyList()),
            )

            assertTrue(loaded.locations.single().isValid)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun saveSubscriptionDraftAddsNewSubscriptionAndActivatesIt() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-add-subscription")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)

            service.toggleAddSubscriptionEditor()
            service.setProfileDraft("https://example.com/new-subscription.txt")
            service.saveSubscriptionDraft()

            val saved = service.state.subscriptions.first()
            assertEquals("https://example.com/new-subscription.txt", saved.url)
            assertEquals(saved.id, service.state.activeSubscriptionId)
            assertEquals(saved.url, service.state.profileUrl)
            assertFalse(service.state.showAddSubscriptionEditor)

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            )
            assertEquals("https://example.com/new-subscription.txt", reloaded.persistedState.subscriptions.first().url)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun saveSubscriptionRefreshPolicyPersistsValidCustomIntervalAndFindBestFlag() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-service-save")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)

            service.setSubscriptionRefreshPolicyDraft(SubscriptionRefreshPolicy.CUSTOM)
            service.setSubscriptionRefreshCustomHoursDraft("0.5")
            service.setFindBestAfterSubscriptionRefreshDraft(false)
            service.saveSubscriptionRefreshPolicy()

            assertEquals(SubscriptionRefreshPolicy.CUSTOM, service.state.subscriptionRefreshPolicy)
            assertEquals("0.5", service.state.subscriptionRefreshCustomHoursDraft)
            assertEquals(0.5, service.state.subscriptionRefreshCustomHours)
            assertFalse(service.state.findBestAfterSubscriptionRefresh)

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            )
            assertEquals(SubscriptionRefreshPolicy.CUSTOM, reloaded.persistedState.subscriptionRefreshPolicy)
            assertEquals(0.5, reloaded.persistedState.subscriptionRefreshCustomHours)
            assertFalse(reloaded.persistedState.findBestAfterSubscriptionRefresh)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun saveSubscriptionRefreshPolicyRejectsTooSmallIntervalWithoutPersisting() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-service-invalid")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)
            val before = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            ).persistedState

            service.setSubscriptionRefreshPolicyDraft(SubscriptionRefreshPolicy.CUSTOM)
            service.setSubscriptionRefreshCustomHoursDraft("0.01")
            service.setFindBestAfterSubscriptionRefreshDraft(false)
            service.saveSubscriptionRefreshPolicy()

            assertTrue(service.state.statusMessage.contains("at least 5 minutes"))

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            ).persistedState
            assertEquals(before.subscriptionRefreshPolicy, reloaded.subscriptionRefreshPolicy)
            assertEquals(before.subscriptionRefreshCustomHours, reloaded.subscriptionRefreshCustomHours)
            assertEquals(before.findBestAfterSubscriptionRefresh, reloaded.findBestAfterSubscriptionRefresh)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun saveAdditionalSettingsPersistsDnsAndValidationSettings() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-additional-settings")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)

            service.toggleDnsDialog()
            service.setUseCustomDnsDraft(true)
            service.setCustomDnsDraft("1.1.1.1")
            service.saveDns()

            assertFalse(service.state.showDnsDialog)
            assertTrue(service.state.useCustomDns)
            assertEquals("1.1.1.1", service.state.customDns)

            service.toggleValidationSettingsDialog()
            service.setValidationPrimaryUrlDraft("google.com/generate_204")
            service.setValidationSecondaryUrlDraft("https://chatgpt.com/")
            service.setValidationBatchSizeDraft("4")
            service.setValidationRetryCountDraft("2")
            service.saveValidationSettings()

            assertFalse(service.state.showValidationSettingsDialog)
            assertEquals("https://google.com/generate_204", service.state.validationSettings.primaryUrl)
            assertEquals("https://chatgpt.com/", service.state.validationSettings.secondaryUrl)
            assertEquals(4, service.state.validationSettings.batchSize)
            assertEquals(2, service.state.validationSettings.retryCount)

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            ).persistedState
            assertTrue(reloaded.useCustomDns)
            assertEquals("1.1.1.1", reloaded.customDns)
            assertEquals("https://google.com/generate_204", reloaded.validationSettings.primaryUrl)
            assertEquals(4, reloaded.validationSettings.batchSize)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun deleteSubscriptionRemovesItAndFallsBackToRemainingSubscription() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-delete-subscription")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(store = store)
            val removed = service.state.subscriptions.first()
            val fallback = service.state.subscriptions[1]

            service.deleteSubscription(removed.id)

            assertEquals(listOf(fallback.id), service.state.subscriptions.map { it.id })
            assertEquals(fallback.id, service.state.activeSubscriptionId)
            assertEquals(fallback.url, service.state.profileUrl)
            assertTrue(service.visibleDesktopLocations().all { it.sourceUrl != removed.url })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun shutdownRemembersRunningVpnForNextLaunchWithoutPersistingLiveRunningState() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-resume-after-shutdown")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(
                store = store,
                forceRunningState = true,
            )

            service.shutdownForExit()

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            )
            assertFalse(reloaded.persistedState.isVpnRunning)
            assertTrue(reloaded.resumeConnectionOnLaunch)
            assertTrue(reloaded.persistedState.selectedProfileRawLink.isNotBlank())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun manualStopDisablesResumeOnNextLaunch() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-no-resume-after-stop")
        try {
            val store = DesktopStateStore(tempDir)
            val service = DesktopAppService.createForTesting(
                store = store,
                forceRunningState = true,
            )

            service.stopDesktopProxy()

            val reloaded = DesktopStateStore(tempDir).loadWorkspace(
                DesktopWorkspace(
                    persistedState = PersistedState(),
                    locations = emptyList(),
                ),
            )
            assertFalse(reloaded.persistedState.isVpnRunning)
            assertFalse(reloaded.resumeConnectionOnLaunch)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun findBestInVpnModeUsesNormalPreconditionsInsteadOfUnsupportedModeGuard() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-vpn-mode-precondition")
        try {
            val service = DesktopAppService.createForTesting(
                store = DesktopStateStore(tempDir),
                initialWorkspace = DesktopWorkspace(
                    persistedState = PersistedState(
                        profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                        appMode = AppMode.VPN,
                        currentLocations = emptyList(),
                        savedLocations = emptyList(),
                    ),
                    locations = emptyList(),
                ),
            )

            service.findBestLocation(refreshSubscriptionsFirst = false)

            assertEquals(AppMode.VPN, service.state.appMode)
            assertTrue(service.state.statusMessage.contains("Add at least one saved location first"))
            assertFalse(service.state.statusMessage.contains("Proxy-only mode only"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun runAutoRefreshCycleRefreshesSupportedSubscriptionsAndTriggersPostRefreshSelection() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-auto-refresh")
        try {
            val subscription = SubscriptionSource(
                id = "desktop-test-subscription",
                url = "https://example.com/subscription.txt",
                customName = "Example",
            )
            val workspace = DesktopWorkspace(
                persistedState = PersistedState(
                    profileUrl = subscription.url,
                    activeSubscriptionId = subscription.id,
                    subscriptions = listOf(subscription),
                    profileHistory = listOf(subscription.url),
                    profileHistoryNames = mapOf(subscription.url to subscription.customName),
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    appMode = AppMode.PROXY_ONLY,
                    subscriptionRefreshPolicy = SubscriptionRefreshPolicy.CUSTOM,
                    findBestAfterSubscriptionRefresh = true,
                    subscriptionRefreshCustomHours = 0.5,
                ),
                locations = emptyList(),
            )
            var postRefreshSelections = 0
            val service = DesktopAppService.createForTesting(
                store = DesktopStateStore(tempDir),
                initialWorkspace = workspace,
                subscriptionContentFetcher = FakeSubscriptionContentFetcher(
                    mapOf(
                        subscription.url to "socks://user:pass@127.0.0.1:1080#Auto%20Refresh",
                    ),
                ),
                autoRefreshBestSelectionAction = { postRefreshSelections += 1 },
                forceRunningState = true,
            )

            service.runAutoRefreshCycle()

            assertEquals(1, postRefreshSelections)
            assertEquals(1, service.state.subscriptions.single().cachedLocations.size)
            assertEquals(1, service.state.currentLocations.size)
            assertTrue(service.state.statusMessage.contains("Subscription refreshed"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun autoRefreshDoesNotStopRunningVpnBeforePostRefreshSelectionWhenSelectedLocationChanged() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-auto-refresh-selected-changed")
        try {
            val subscription = SubscriptionSource(
                id = "desktop-test-subscription",
                url = "https://example.com/subscription.txt",
                customName = "Example",
                cachedLocations = listOf("stale-selected-location"),
            )
            val workspace = DesktopWorkspace(
                persistedState = PersistedState(
                    profileUrl = subscription.url,
                    activeSubscriptionId = subscription.id,
                    subscriptions = listOf(subscription),
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    appMode = AppMode.VPN,
                    findBestAfterSubscriptionRefresh = true,
                    selectedProfileName = "Old Location",
                    selectedProfileServer = "192.0.2.1",
                    selectedProfileRawLink = "stale-selected-location",
                    selectedProfileSourceUrl = subscription.url,
                    isVpnRunning = true,
                ),
                locations = listOf(
                    DesktopLocationRecord(
                        index = 1,
                        sourceUrl = subscription.url,
                        rawLink = "stale-selected-location",
                        name = "Old Location",
                        server = "192.0.2.1",
                        details = "SOCKS",
                        benchmarkDetail = "Imported • not checked yet",
                        isValid = true,
                        isSelected = true,
                    ),
                ),
            )
            var postRefreshSelections = 0
            val service = DesktopAppService.createForTesting(
                store = DesktopStateStore(tempDir),
                initialWorkspace = workspace,
                subscriptionContentFetcher = FakeSubscriptionContentFetcher(
                    mapOf(
                        subscription.url to "socks://user:pass@127.0.0.1:1080#New%20Location",
                    ),
                ),
                autoRefreshBestSelectionAction = { postRefreshSelections += 1 },
                forceRunningState = true,
            )

            service.runAutoRefreshCycle()

            assertEquals(1, postRefreshSelections)
            assertTrue(service.state.isVpnRunning)
            assertTrue(service.state.connectionLog.none { it.message.contains("removed the selected location") })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun refreshKeepsSelectedLocationWhenSubscriptionRebuildChangesRawLinkOnly() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-desktop-refresh-selected-remap")
        try {
            val subscription = SubscriptionSource(
                id = "desktop-test-subscription",
                url = "https://example.com/subscription.txt",
                customName = "Example",
                cachedLocations = listOf("stale-selected-location"),
            )
            val workspace = DesktopWorkspace(
                persistedState = PersistedState(
                    profileUrl = subscription.url,
                    activeSubscriptionId = subscription.id,
                    subscriptions = listOf(subscription),
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    appMode = AppMode.VPN,
                    selectedProfileName = "Auto Refresh",
                    selectedProfileServer = "127.0.0.1",
                    selectedProfileRawLink = "stale-selected-location",
                    selectedProfileSourceUrl = subscription.url,
                    isVpnRunning = true,
                ),
                locations = listOf(
                    DesktopLocationRecord(
                        index = 1,
                        sourceUrl = subscription.url,
                        rawLink = "stale-selected-location",
                        name = "Auto Refresh",
                        server = "127.0.0.1",
                        details = "SOCKS",
                        benchmarkDetail = "Imported • not checked yet",
                        isValid = true,
                        isSelected = true,
                    ),
                ),
            )
            val service = DesktopAppService.createForTesting(
                store = DesktopStateStore(tempDir),
                initialWorkspace = workspace,
                subscriptionContentFetcher = FakeSubscriptionContentFetcher(
                    mapOf(
                        subscription.url to "socks://user:pass@127.0.0.1:1080#Auto%20Refresh",
                    ),
                ),
                forceRunningState = true,
            )

            service.refreshActiveSubscriptions()

            assertTrue(service.state.isVpnRunning)
            assertEquals("Auto Refresh", service.state.selectedProfileName)
            assertEquals("127.0.0.1", service.state.selectedProfileServer)
            assertTrue(service.state.selectedProfileRawLink.isNotBlank())
            assertFalse(service.state.selectedProfileRawLink == "stale-selected-location")
            assertTrue(service.state.connectionLog.none { it.message.contains("removed the selected location") })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun benchmarkPreflightReachableLocationsRemainSelectable() {
        assertTrue(
            benchmarkDetailIndicatesSelectable(
                detail = "Example: tcp=80.0ms",
                previousIsValid = false,
            ),
        )
        assertTrue(
            benchmarkDetailIndicatesSelectable(
                detail = "Example  tcp 80.0ms",
                previousIsValid = false,
            ),
        )
        assertFalse(
            benchmarkDetailIndicatesSelectable(
                detail = "Example: tcp=unreachable",
                previousIsValid = true,
            ),
        )
        assertTrue(
            benchmarkDetailIndicatesSelectable(
                detail = "Example: tcp=39.4ms primary=ok primary_codes=204 secondary=ok secondary_codes=200",
                previousIsValid = false,
            ),
        )
        assertTrue(
            benchmarkDetailIndicatesSelectable(
                detail = "primary ok • secondary challenge • tcp 39.4ms",
                previousIsValid = false,
            ),
        )
        assertFalse(
            benchmarkDetailIndicatesSelectable(
                detail = "Example: tcp=46.4ms primary=bad primary_codes=000 secondary=bad secondary_codes=000",
                previousIsValid = true,
            ),
        )
        assertFalse(
            benchmarkDetailIndicatesSelectable(
                detail = "primary bad • secondary bad • tcp 46.4ms",
                previousIsValid = true,
            ),
        )
    }
}

private class FakeSubscriptionContentFetcher(
    private val payloadsByUrl: Map<String, String>,
) : SubscriptionContentFetcher {
    override suspend fun fetch(url: String): FetchedSubscriptionContent {
        return FetchedSubscriptionContent(
            body = payloadsByUrl[url] ?: error("Unexpected subscription fetch: $url"),
            contentType = "text/plain",
        )
    }
}
