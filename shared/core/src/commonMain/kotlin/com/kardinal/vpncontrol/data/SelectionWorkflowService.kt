package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

data class SubscriptionSearchTarget(
    val subscriptionId: String,
    val sourceUrl: String,
    val displayName: String,
)

data class LoadedSubscriptionProfiles(
    val profilesById: Map<String, List<ProxyProfile>>,
    val profileSourceTargets: Map<String, SubscriptionSearchTarget>,
    val failureMessages: List<String>,
) {
    val allProfiles: List<ProxyProfile>
        get() = profilesById.values.flatten()
}

object SelectionWorkflowService {
    fun subscriptionSearchTargets(
        state: PersistedState,
        labelForSource: (String) -> String?,
    ): List<SubscriptionSearchTarget> {
        return if (isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)) {
            state.subscriptions
                .filter { it.url.isNotBlank() }
                .map { subscription ->
                    SubscriptionSearchTarget(
                        subscriptionId = subscription.id,
                        sourceUrl = subscription.url,
                        displayName = subscription.customName.ifBlank {
                            labelForSource(subscription.url) ?: "subscription"
                        },
                    )
                }
        } else {
            state.subscriptions
                .firstOrNull { it.id == state.activeSubscriptionId && it.url.isNotBlank() }
                ?.let { subscription ->
                    SubscriptionSearchTarget(
                        subscriptionId = subscription.id,
                        sourceUrl = subscription.url,
                        displayName = subscription.customName.ifBlank {
                            labelForSource(subscription.url) ?: "subscription"
                        },
                    )
                }
                ?.let(::listOf)
                .orEmpty()
        }
    }

    suspend fun loadProfilesForTargets(
        targets: List<SubscriptionSearchTarget>,
        onStatus: suspend (String) -> Unit,
        loadProfiles: suspend (String) -> List<ProxyProfile>,
        concurrency: Int = 1,
    ): LoadedSubscriptionProfiles = coroutineScope {
        val normalizedConcurrency = concurrency.coerceAtLeast(1)
        val semaphore = Semaphore(normalizedConcurrency)
        val results = targets.mapIndexed { index, target ->
            async {
                semaphore.withPermit {
                    loadProfilesForTarget(
                        index = index,
                        target = target,
                        targetCount = targets.size,
                        onStatus = onStatus,
                        loadProfiles = loadProfiles,
                    )
                }
            }
        }.awaitAll().sortedBy(TargetLoadResult::index)

        val loadedProfilesById = linkedMapOf<String, List<ProxyProfile>>()
        val profileSourceTargets = linkedMapOf<String, SubscriptionSearchTarget>()
        val failureMessages = mutableListOf<String>()

        results.forEach { result ->
            if (result.failureMessage != null) {
                failureMessages += result.failureMessage
                return@forEach
            }
            val profiles = result.profiles.orEmpty()
            loadedProfilesById[result.target.subscriptionId] = profiles
            profiles.forEach { profile ->
                profileSourceTargets[LocationConfigs.encodeStoredLocation(profile)] = result.target
            }
        }

        LoadedSubscriptionProfiles(
            profilesById = loadedProfilesById,
            profileSourceTargets = profileSourceTargets,
            failureMessages = failureMessages,
        )
    }

    suspend fun parseRemoteSourceLocations(
        rawSource: String,
        resolveSource: (String) -> ResolvedRemoteSource,
        fetchedContent: suspend (String) -> FetchedSubscriptionContent,
    ): List<ProxyProfile> {
        val resolved = resolveSource(rawSource)
        val fetchUrl = resolved.fetchUrl ?: error("Remote source did not produce any locations")
        val downloaded = fetchedContent(fetchUrl)
        SubscriptionPayloadInspector.detectPayloadError(
            body = downloaded.body,
            contentType = downloaded.contentType,
        )?.let { error(it) }
        val profiles = runCatching {
            ProxyParser.parseSubscription(downloaded.body)
        }.getOrElse { error ->
            val baseMessage = SubscriptionPayloadInspector.invalidPayloadMessage(error)
            if (resolved.preview.kindLabel.equals("Subscription URL", ignoreCase = true)) {
                throw IllegalArgumentException(baseMessage, error)
            }
            throw IllegalArgumentException(
                "${resolved.preview.kindLabel} resolved successfully, but ${baseMessage.replaceFirstChar(Char::lowercaseChar)}",
                error,
            )
        }
        SubscriptionPayloadInspector.parsedProfileError(
            profiles = profiles,
            responseHeaders = downloaded.headers,
        )?.let { message ->
            throw IllegalArgumentException(message)
        }
        return profiles
    }

    private suspend fun loadProfilesForTarget(
        index: Int,
        target: SubscriptionSearchTarget,
        targetCount: Int,
        onStatus: suspend (String) -> Unit,
        loadProfiles: suspend (String) -> List<ProxyProfile>,
    ): TargetLoadResult {
        val sourceLabel = if (targetCount == 1) {
            "selected subscription"
        } else {
            target.displayName
        }
        onStatus(BenchmarkStatusMessages.resolvingRemoteSource(sourceLabel))
        val profilesResult = runCatching { loadProfiles(target.sourceUrl) }
        if (profilesResult.isFailure) {
            val error = profilesResult.exceptionOrNull()
            return TargetLoadResult(
                index = index,
                target = target,
                failureMessage = error?.message ?: BenchmarkStatusMessages.subscriptionSourceLoadFailed(sourceLabel),
            )
        }
        val profiles = profilesResult.getOrThrow()
        if (profiles.isEmpty()) {
            return TargetLoadResult(
                index = index,
                target = target,
                failureMessage = if (targetCount == 1) {
                    BenchmarkStatusMessages.noLocationsFoundSelectedSubscription()
                } else {
                    BenchmarkStatusMessages.noLocationsFoundInSource(sourceLabel)
                },
            )
        }
        return TargetLoadResult(
            index = index,
            target = target,
            profiles = profiles,
        )
    }
}

private data class TargetLoadResult(
    val index: Int,
    val target: SubscriptionSearchTarget,
    val profiles: List<ProxyProfile>? = null,
    val failureMessage: String? = null,
)
