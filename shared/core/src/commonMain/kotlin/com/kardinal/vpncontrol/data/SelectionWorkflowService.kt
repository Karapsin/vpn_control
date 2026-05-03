package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent

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
    ): LoadedSubscriptionProfiles {
        val loadedProfilesById = linkedMapOf<String, List<ProxyProfile>>()
        val profileSourceTargets = linkedMapOf<String, SubscriptionSearchTarget>()
        val failureMessages = mutableListOf<String>()

        for (target in targets) {
            val sourceLabel = if (targets.size == 1) {
                "selected subscription"
            } else {
                target.displayName
            }
            onStatus(StatusMessages.resolvingRemoteSource(sourceLabel))
            val profilesResult = runCatching { loadProfiles(target.sourceUrl) }
            if (profilesResult.isFailure) {
                val error = profilesResult.exceptionOrNull()
                failureMessages += error?.message ?: StatusMessages.subscriptionSourceLoadFailed(sourceLabel)
                continue
            }
            val profiles = profilesResult.getOrThrow()
            if (profiles.isEmpty()) {
                val message = if (targets.size == 1) {
                    StatusMessages.noLocationsFoundSelectedSubscription()
                } else {
                    StatusMessages.noLocationsFoundInSource(sourceLabel)
                }
                failureMessages += message
                continue
            }

            loadedProfilesById[target.subscriptionId] = profiles
            profiles.forEach { profile ->
                profileSourceTargets[LocationConfigs.encodeStoredLocation(profile)] = target
            }
        }

        return LoadedSubscriptionProfiles(
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
}
