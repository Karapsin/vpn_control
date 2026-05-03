package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.sourceUrlForStoredLocation
import com.kardinal.vpncontrol.shared.storageapi.SearchStateStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.IOException

class BenchmarkOrchestrator(
    private val context: android.content.Context,
    private val storage: SearchStateStore,
) {
    data class SubscriptionSyncResult(
        val selectedMissing: Boolean,
    )

    private val browserUserAgent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    private val subscriptionUserAgent = "VPNControl/1.0 (Android)"
    private val settings = ValidationRuntimeSettings()
    private val genericSecondaryBlockedMarkers = listOf(
        "not available in your country",
        "not available in your region",
        "not available in your country, region, or territory",
        "unsupported country",
        "service is unavailable in your country",
        "service is not available in your country",
        "this content is not available in your country",
        "access from your country is not allowed",
        "unavailable in your country",
    )
    private val chatGptBlockedMarkers = listOf(
        "openai's services are not available in your country",
        "you do not have access to chat.openai.com",
    )
    private val downloadClient = SubscriptionDownloadClient(subscriptionUserAgent)
    private val validationRuntime = ProxyValidationRuntime(
        context = context,
        browserUserAgent = browserUserAgent,
        genericSecondaryBlockedMarkers = genericSecondaryBlockedMarkers,
        chatGptBlockedMarkers = chatGptBlockedMarkers,
    )

    suspend fun refreshBestProfile(): Result<ProfileSelection> = withContext(Dispatchers.IO) {
        try {
            Result.success(
                withTimeout(settings.refreshTimeoutMillis) {
                    val state = storage.snapshot()
                    val validationSettings = state.validationSettings.normalized()
                    val benchmarkUrls = BenchmarkUrls(
                        primary = validationSettings.primaryUrl,
                        secondary = validationSettings.secondaryUrl,
                    )
                    val dnsSettings = DnsSettings(
                        enabled = state.useCustomDns,
                        value = state.customDns,
                    )
                    when (state.profileSourceMode) {
                        ProfileSourceMode.SUBSCRIPTION -> {
                            val searchTargets = subscriptionSearchTargets(state)
                            require(searchTargets.isNotEmpty()) { "Remote source is empty" }
                            val benchmarkDetails = linkedMapOf<String, String>()
                            val allSubscriptionsMode =
                                isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
                            val loaded = SelectionWorkflowService.loadProfilesForTargets(
                                targets = searchTargets,
                                onStatus = storage::updateStatus,
                                loadProfiles = ::loadRemoteSourceLocations,
                            )
                            val loadedProfiles = loaded.allProfiles
                            require(loadedProfiles.isNotEmpty()) {
                                loaded.failureMessages.lastOrNull()?.takeIf { it.isNotBlank() }
                                    ?: BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()
                            }

                            val evaluation = evaluateProfilesForSelection(
                                profiles = loadedProfiles,
                                validationSettings = validationSettings,
                                dnsSettings = dnsSettings,
                                benchmarkUrls = benchmarkUrls,
                                sourceKey = if (allSubscriptionsMode) {
                                    "ALL_SUBSCRIPTIONS"
                                } else {
                                    "SELECTED_SUBSCRIPTION"
                                },
                            )
                            benchmarkDetails.putAll(evaluation.locationBenchmarkDetails)

                            val selectedBenchmark = evaluation.winner ?: evaluation.fallback ?: run {
                                error(
                                    evaluation.failureMessage?.takeIf { it.isNotBlank() }
                                        ?: loaded.failureMessages.lastOrNull()?.takeIf { it.isNotBlank() }
                                        ?: "No location fully reached the secondary site",
                                )
                            }
                            val selectedTarget = loaded.profileSourceTargets[
                                LocationConfigs.encodeStoredLocation(selectedBenchmark.profile)
                            ] ?: error("No subscription source was selected")

                            loaded.profilesById.forEach { (subscriptionId, profiles) ->
                                if (subscriptionId == state.activeSubscriptionId) {
                                    storage.updateCurrentLocations(profiles.map { it.rawLink })
                                } else {
                                    storage.updateSubscriptionCache(subscriptionId, profiles.map { it.rawLink })
                                }
                            }
                            storage.updateLocationBenchmarkDetails(benchmarkDetails)

                            val runtimeConfig = buildRuntimeConfig(
                                profile = selectedBenchmark.profile,
                                state = state,
                                dnsSettings = dnsSettings,
                            )
                            ProfileSelection(
                                profile = selectedBenchmark.profile,
                                benchmark = selectedBenchmark,
                                runtimeConfigJson = runtimeConfig,
                                sourceUrl = selectedTarget.sourceUrl,
                            )
                        }
                        ProfileSourceMode.CURRENT_LOCATIONS -> {
                            storage.updateStatus(BenchmarkStatusMessages.loadingSavedLocations())
                            val profiles = decodeStoredLocations(state.currentLocations)
                            require(profiles.isNotEmpty()) { "No saved locations available" }
                            val evaluation = evaluateProfilesForSelection(
                                profiles = profiles,
                                validationSettings = validationSettings,
                                dnsSettings = dnsSettings,
                                benchmarkUrls = benchmarkUrls,
                                sourceKey = "SAVED_LOCATIONS",
                            )
                            val winner = evaluation.winner ?: evaluation.fallback ?: run {
                                storage.updateLocationBenchmarkDetails(evaluation.locationBenchmarkDetails)
                                error(evaluation.failureMessage ?: "No location fully reached the secondary site")
                            }

                            storage.updateLocationBenchmarkDetails(evaluation.locationBenchmarkDetails)

                            val runtimeConfig = buildRuntimeConfig(
                                profile = winner.profile,
                                state = state,
                                dnsSettings = dnsSettings,
                            )
                            ProfileSelection(
                                profile = winner.profile,
                                benchmark = winner,
                                runtimeConfigJson = runtimeConfig,
                            )
                        }
                    }
                },
            )
        } catch (_: TimeoutCancellationException) {
            Result.failure(IOException("Location search timed out after ${settings.refreshTimeoutMillis / 1000}s"))
        } catch (error: Throwable) {
            Result.failure(error)
        }
    }

    suspend fun syncSubscriptionLocations(): Result<SubscriptionSyncResult> = withContext(Dispatchers.IO) {
        runCatching {
            val state = storage.snapshot()
            val targets = subscriptionSearchTargets(state)
            require(targets.isNotEmpty()) { "Remote source is empty" }
            var selectedMissing = false
            targets.forEach { target ->
                val parsed = loadRemoteSourceLocations(target.sourceUrl)
                require(parsed.isNotEmpty()) { BenchmarkStatusMessages.noLocationsFoundInSource(target.displayName) }
                val update = storage.updateSubscriptionCache(
                    subscriptionId = target.subscriptionId,
                    rawLinks = parsed.map { it.rawLink },
                )
                selectedMissing = selectedMissing || update.selectedMissing
            }
            SubscriptionSyncResult(
                selectedMissing = selectedMissing,
            )
        }
    }

    suspend fun fetchSubscriptionLocations(rawSource: String): Result<List<ProxyProfile>> = withContext(Dispatchers.IO) {
        runCatching { loadRemoteSourceLocations(rawSource) }
    }

    suspend fun benchmarkLocation(rawLink: String): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        runCatching {
            withTimeout(settings.refreshTimeoutMillis) {
                val state = storage.snapshot()
                val validationSettings = state.validationSettings.normalized()
                val benchmarkUrls = BenchmarkUrls(
                    primary = validationSettings.primaryUrl,
                    secondary = validationSettings.secondaryUrl,
                )
                val profile = LocationConfigs.decodeStoredLocation(rawLink)
                val normalizedRawLink = LocationConfigs.encodeStoredLocation(profile)
                val dnsSettings = DnsSettings(
                    enabled = state.useCustomDns,
                    value = state.customDns,
                )

                if (profile.protocol == ProxyProtocol.CUSTOM) {
                    val benchmark = ProfileBenchmark(
                        profile = profile,
                        primaryStatus = "manual",
                        secondaryStatus = "manual",
                        primaryTotal = null,
                        secondaryTotal = null,
                        score = Double.POSITIVE_INFINITY,
                        detail = "${profile.remarks}: custom_config_manual_only",
                    )
                    val updatedDetails = state.locationBenchmarkDetails.toMutableMap()
                    updatedDetails[normalizedRawLink] = benchmark.detail
                    storage.updateLocationBenchmarkDetails(updatedDetails)
                    return@withTimeout benchmark
                }

                storage.updateStatus(BenchmarkStatusMessages.checkingTcpSpeed(profile.remarks))
                val preflight = validationRuntime.preflightProfile(profile, settings)
                val updatedDetails = state.locationBenchmarkDetails.toMutableMap()

                val benchmark = if (preflight.connectMillis == null) {
                    BenchmarkSearchLogic.failedBenchmark(profile, preflight, "unreachable")
                } else {
                    storage.updateStatus(LocationStatusMessages.testingLocation(profile.remarks))
                    benchmarkPreflightCandidate(
                        candidate = preflight,
                        idx = 0,
                        dnsSettings = dnsSettings,
                        benchmarkUrls = benchmarkUrls,
                    )
                }

                updatedDetails[normalizedRawLink] = benchmark.detail
                storage.updateLocationBenchmarkDetails(updatedDetails)
                benchmark
            }
        }
    }

    suspend fun rehydrateSelection(state: PersistedState): Result<ProfileSelection> = withContext(Dispatchers.Default) {
        runCatching {
            val storedSelection = state.selectedProfileJson.ifBlank {
                    state.selectedProfileRawLink.ifBlank {
                    storage.readLastSelectedProfile().orEmpty()
                }
            }
            val profile = if (storedSelection.isNotBlank()) {
                LocationConfigs.decodeStoredLocation(storedSelection)
            } else {
                cachedProfile(state)
            }
            val dnsSettings = DnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            )
            ProfileSelection(
                profile = profile,
                benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "cached",
                    secondaryStatus = "cached",
                    primaryTotal = null,
                    secondaryTotal = null,
                    score = 0.0,
                    detail = state.lastBenchmarkSummary.ifBlank { "Using cached selection" },
                ),
                runtimeConfigJson = if (profile.rawLink.isNotBlank()) {
                    buildRuntimeConfig(
                        profile = profile,
                        state = state,
                        dnsSettings = dnsSettings,
                    )
                } else {
                    state.runtimeConfigJson
                },
                sourceUrl = state.selectedProfileSourceUrl,
            )
        }
    }

    suspend fun selectionFromRawLink(
        state: PersistedState,
        rawLink: String,
        detail: String,
    ): Result<ProfileSelection> = withContext(Dispatchers.Default) {
        runCatching {
            val profile = LocationConfigs.parseLocationInput(rawLink)
            val dnsSettings = DnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            )
            ProfileSelection(
                profile = profile,
                benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "manual",
                    secondaryStatus = "manual",
                    primaryTotal = null,
                    secondaryTotal = null,
                    score = 0.0,
                    detail = detail,
                ),
                runtimeConfigJson = buildRuntimeConfig(
                    profile = profile,
                    state = state,
                    dnsSettings = dnsSettings,
                ),
                sourceUrl = if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                    if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
                        sourceUrlForStoredLocation(state.subscriptions, LocationConfigs.encodeStoredLocation(profile))
                    } else {
                        state.profileUrl
                    }
                } else {
                    state.selectedProfileSourceUrl
                },
            )
        }
    }

    private fun subscriptionSearchTargets(state: PersistedState): List<SubscriptionSearchTarget> {
        return SelectionWorkflowService.subscriptionSearchTargets(state) { url ->
            RemoteSourceResolver.preview(url)?.title
        }
    }

    private suspend fun evaluateProfilesForSelection(
        profiles: List<ProxyProfile>,
        validationSettings: com.kardinal.vpncontrol.model.BenchmarkValidationSettings,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        sourceKey: String,
    ): SearchEvaluation {
        val benchmarkableProfiles = profiles.filterNot { it.protocol == ProxyProtocol.CUSTOM }
        storage.updateStatus(BenchmarkStatusMessages.checkingLocationSource(profiles.size, sourceKey))
        val preflightResults = validationRuntime.preflightProfiles(benchmarkableProfiles, settings)
        val reachableProfiles = preflightResults
            .filter { it.connectMillis != null }
            .sortedBy { it.connectMillis }

        val walk = if (benchmarkableProfiles.isNotEmpty() && reachableProfiles.isNotEmpty()) {
            storage.updateStatus(
                BenchmarkStatusMessages.testingFastestCandidates(),
            )
            validateInBatchesUntilSuccess(
                candidates = reachableProfiles,
                batchSize = validationSettings.batchSize,
                dnsSettings = dnsSettings,
                benchmarkUrls = benchmarkUrls,
            ) { benchmark ->
                benchmark.primaryStatus == "ok" && benchmark.secondaryStatus == "ok"
            }
        } else {
            ValidationWalkResult(
                benchmarks = emptyList(),
                winner = null,
            )
        }
        return BenchmarkSearchLogic.evaluateProfilesForSelection(
            profiles = profiles,
            preflightResults = preflightResults,
            candidateBenchmarks = walk.benchmarks,
            winner = walk.winner,
        )
    }

    private fun cachedProfile(state: PersistedState): ProxyProfile {
        val name = state.selectedProfileName.ifBlank { "Cached selection" }
        val server = state.selectedProfileServer.ifBlank { "cached" }
        return ProxyProfile(
            remarks = name,
            uuid = "",
            server = server,
            serverPort = 443,
            network = "tcp",
            flow = "",
            security = "",
            sni = server,
            fingerprint = "chrome",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "none",
            rawLink = "",
        )
    }

    private fun buildRuntimeConfig(
        profile: ProxyProfile,
        state: PersistedState,
        dnsSettings: DnsSettings,
    ): String {
        if (profile.protocol == ProxyProtocol.CUSTOM) {
            require(profile.customConfigJson.isNotBlank()) { "Custom config is empty" }
            return profile.customConfigJson
        }
        return when (state.appMode) {
            AppMode.VPN -> SingBoxConfigFactory.buildTunConfig(
                profile = profile,
                dns = dnsSettings,
                routingRules = state.routingRules,
            )
            AppMode.PROXY_ONLY -> SingBoxConfigFactory.buildProxyOnlyConfig(
                profile = profile,
                dns = dnsSettings,
                routingRules = state.routingRules,
            )
        }
    }

    private suspend fun loadRemoteSourceLocations(rawSource: String): List<ProxyProfile> {
        storage.updateStatus(BenchmarkStatusMessages.downloadingRemoteSource())
        val subscriptionHwid = storage.ensureSubscriptionHwid()
        return SelectionWorkflowService.parseRemoteSourceLocations(
            rawSource = rawSource,
            resolveSource = RemoteSourceResolver::resolveForFetch,
            fetchedContent = { url ->
                downloadClient.fetch(
                    url = url,
                    timeoutSeconds = settings.subscriptionMaxTimeSeconds,
                    subscriptionHwid = subscriptionHwid,
                )
            },
        )
    }

    private fun decodeStoredLocations(storedLocations: List<String>): List<ProxyProfile> {
        return storedLocations.mapIndexed { index, stored ->
            runCatching { LocationConfigs.decodeStoredLocation(stored) }
                .getOrElse { error("Invalid saved location #${index + 1}: ${it.message}") }
        }
    }

    private suspend fun validateInBatchesUntilSuccess(
        candidates: List<PreflightResult>,
        batchSize: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
        isWinner: (ProfileBenchmark) -> Boolean,
    ): ValidationWalkResult = coroutineScope {
        val benchmarks = mutableListOf<ProfileBenchmark>()
        val normalizedBatchSize = batchSize.coerceAtLeast(1)
        val validationConcurrency = minOf(normalizedBatchSize, 5)
        val semaphore = Semaphore(validationConcurrency)
        for ((batchIndex, batch) in candidates.chunked(normalizedBatchSize).withIndex()) {
            val start = batchIndex * normalizedBatchSize + 1
            val end = start + batch.size - 1
            storage.updateStatus(
                BenchmarkStatusMessages.testingLocationsRange(start, end, candidates.size),
            )
            val batchBenchmarks = batch.mapIndexed { offset, candidate ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        benchmarkPreflightCandidate(
                            candidate = candidate,
                            idx = (start - 1) + offset,
                            dnsSettings = dnsSettings,
                            benchmarkUrls = benchmarkUrls,
                        )
                    }
                }
            }.awaitAll()
            benchmarks += batchBenchmarks
            val winner = batchBenchmarks.firstOrNull(isWinner)
            if (winner != null) {
                return@coroutineScope ValidationWalkResult(
                    benchmarks = benchmarks,
                    winner = winner,
                )
            }
        }
        ValidationWalkResult(
            benchmarks = benchmarks,
            winner = null,
        )
    }

    private suspend fun benchmarkPreflightCandidate(
        candidate: PreflightResult,
        idx: Int,
        dnsSettings: DnsSettings,
        benchmarkUrls: BenchmarkUrls,
    ): ProfileBenchmark {
        return validationRuntime.benchmarkCandidate(
            candidate = candidate,
            idx = idx,
            dnsSettings = dnsSettings,
            benchmarkUrls = benchmarkUrls,
            settings = settings,
        )
    }
}
