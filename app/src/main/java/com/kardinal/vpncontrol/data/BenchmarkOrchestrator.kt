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
import java.net.ServerSocket
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
    private val countryResolver = AndroidRemoteCountryResolver()
    private val downloadClient = SubscriptionDownloadClient(subscriptionUserAgent)
    private val validationRuntime = ProxyValidationRuntime(
        context = context,
        browserUserAgent = browserUserAgent,
        genericSecondaryBlockedMarkers = genericSecondaryBlockedMarkers,
        chatGptBlockedMarkers = chatGptBlockedMarkers,
        candidateCountryResolver = countryResolver,
    )
    private val activeConnectionVerifier = AndroidActiveConnectionVerifier(
        browserUserAgent = browserUserAgent,
        genericSecondaryBlockedMarkers = genericSecondaryBlockedMarkers,
        chatGptBlockedMarkers = chatGptBlockedMarkers,
    )

    suspend fun refreshBestProfileAttemptPlan(): Result<ProfileSelectionAttemptPlan> = withContext(Dispatchers.IO) {
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
                                concurrency = validationSettings.subscriptionRefreshConcurrency,
                            )
                            val loadedProfiles = loaded.allProfiles
                            require(loadedProfiles.isNotEmpty()) {
                                loaded.failureMessages.lastOrNull()?.takeIf { it.isNotBlank() }
                                    ?: BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()
                            }

                            val attemptPlan = evaluateProfilesForSelection(
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
                            benchmarkDetails.putAll(attemptPlan.locationBenchmarkDetails)

                            loaded.profilesById.forEach { (subscriptionId, profiles) ->
                                if (subscriptionId == state.activeSubscriptionId) {
                                    storage.updateCurrentLocations(profiles.map { it.rawLink })
                                } else {
                                    storage.updateSubscriptionCache(subscriptionId, profiles.map { it.rawLink })
                                }
                            }
                            storage.updateLocationBenchmarkDetails(benchmarkDetails)

                            val attempts = attemptPlan.orderedAttempts.map { preflight ->
                                val selectedTarget = loaded.profileSourceTargets[
                                    LocationConfigs.encodeStoredLocation(preflight.profile)
                                ] ?: error("No subscription source was selected")
                                val activeVerificationPort = activeVerificationPortFor(state.appMode)
                                ProfileSelectionAttempt(
                                    selection = ProfileSelection(
                                        profile = preflight.profile,
                                        benchmark = preflight.toPreflightBenchmark(),
                                        runtimeConfigJson = buildRuntimeConfig(
                                            profile = preflight.profile,
                                            state = state,
                                            dnsSettings = dnsSettings,
                                            activeVerificationPort = activeVerificationPort,
                                        ),
                                        sourceUrl = selectedTarget.sourceUrl,
                                    ),
                                    preflight = preflight,
                                    activeVerificationPort = activeVerificationPort,
                                )
                            }
                            ProfileSelectionAttemptPlan(
                                attempts = attempts,
                                locationBenchmarkDetails = benchmarkDetails,
                                failureMessage = attemptPlan.failureMessage
                                    ?: loaded.failureMessages.lastOrNull()?.takeIf { it.isNotBlank() },
                            )
                        }
                        ProfileSourceMode.CURRENT_LOCATIONS -> {
                            storage.updateStatus(BenchmarkStatusMessages.loadingSavedLocations())
                            val profiles = decodeStoredLocations(state.currentLocations)
                            require(profiles.isNotEmpty()) { "No saved locations available" }
                            val attemptPlan = evaluateProfilesForSelection(
                                profiles = profiles,
                                validationSettings = validationSettings,
                                dnsSettings = dnsSettings,
                                benchmarkUrls = benchmarkUrls,
                                sourceKey = "SAVED_LOCATIONS",
                            )
                            storage.updateLocationBenchmarkDetails(attemptPlan.locationBenchmarkDetails)
                            val attempts = attemptPlan.orderedAttempts.map { preflight ->
                                val activeVerificationPort = activeVerificationPortFor(state.appMode)
                                ProfileSelectionAttempt(
                                    selection = ProfileSelection(
                                        profile = preflight.profile,
                                        benchmark = preflight.toPreflightBenchmark(),
                                        runtimeConfigJson = buildRuntimeConfig(
                                            profile = preflight.profile,
                                            state = state,
                                            dnsSettings = dnsSettings,
                                            activeVerificationPort = activeVerificationPort,
                                        ),
                                    ),
                                    preflight = preflight,
                                    activeVerificationPort = activeVerificationPort,
                                )
                            }
                            ProfileSelectionAttemptPlan(
                                attempts = attempts,
                                locationBenchmarkDetails = attemptPlan.locationBenchmarkDetails,
                                failureMessage = attemptPlan.failureMessage,
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

    suspend fun verifyActiveSelection(attempt: ProfileSelectionAttempt): Result<ProfileBenchmark> = withContext(Dispatchers.IO) {
        val state = storage.snapshot()
        val validationSettings = state.validationSettings.normalized()
        activeConnectionVerifier.verify(
            attempt = attempt,
            url = validationSettings.secondaryUrl,
            settings = settings,
        )
    }

    suspend fun syncSubscriptionLocations(): Result<SubscriptionSyncResult> = withContext(Dispatchers.IO) {
        runCatching {
            val state = storage.snapshot()
            val targets = subscriptionSearchTargets(state)
            require(targets.isNotEmpty()) { "Remote source is empty" }
            val loaded = SelectionWorkflowService.loadProfilesForTargets(
                targets = targets,
                onStatus = storage::updateStatus,
                loadProfiles = ::loadRemoteSourceLocations,
                concurrency = state.validationSettings.normalized().subscriptionRefreshConcurrency,
            )
            require(loaded.allProfiles.isNotEmpty()) {
                loaded.failureMessages.lastOrNull()?.takeIf { it.isNotBlank() }
                    ?: BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()
            }
            var selectedMissing = false
            loaded.profilesById.forEach { (subscriptionId, profiles) ->
                val update = storage.updateSubscriptionCache(
                    subscriptionId = subscriptionId,
                    rawLinks = profiles.map { it.rawLink },
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
    ): BestCandidateAttemptPlan {
        val benchmarkableProfiles = profiles.filterNot { it.protocol == ProxyProtocol.CUSTOM }
        storage.updateStatus(BenchmarkStatusMessages.detectingCountry())
        val userCountry = countryResolver.resolveUserCountryCode()
        storage.updateStatus(BenchmarkStatusMessages.checkingLocationSource(profiles.size, sourceKey))
        val preflightResults = validationRuntime.preflightProfiles(benchmarkableProfiles, settings)
        val plan = BenchmarkSearchLogic.planActiveVerificationAttempts(
            profiles = profiles,
            preflightResults = preflightResults,
            userCountryCode = userCountry,
        )
        if (plan.excluded.isNotEmpty()) {
            storage.updateStatus(BenchmarkStatusMessages.excludingSameCountryLocations(plan.excluded.size))
        }
        return plan
    }

    private fun activeVerificationPortFor(appMode: AppMode): Int {
        return when (appMode) {
            AppMode.PROXY_ONLY -> SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT
            AppMode.VPN -> ServerSocket(0).use { it.localPort }
        }
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
        activeVerificationPort: Int? = null,
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
                activeVerificationPort = activeVerificationPort,
            )
            AppMode.PROXY_ONLY -> SingBoxConfigFactory.buildProxyOnlyConfig(
                profile = profile,
                dns = dnsSettings,
                routingRules = state.routingRules,
                listenPort = activeVerificationPort ?: SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT,
            )
        }
    }

    private fun PreflightResult.toPreflightBenchmark(): ProfileBenchmark {
        return ProfileBenchmark(
            profile = profile,
            primaryStatus = "manual",
            secondaryStatus = "manual",
            primaryTotal = null,
            secondaryTotal = null,
            score = sortScore,
            detail = detail,
        )
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
