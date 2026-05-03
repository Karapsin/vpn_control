package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive

data class SubscriptionSavePlan(
    val nextState: MainUiState,
    val statusMessage: String,
)

data class SubscriptionDeletePlan(
    val target: SubscriptionSource,
    val removedSelected: Boolean,
    val nextState: MainUiState,
    val statusMessage: String,
)

data class SubscriptionRenamePlan(
    val source: String,
    val normalizedSource: String,
    val normalizedName: String,
    val sourceChanged: Boolean,
    val nextState: MainUiState,
    val statusMessage: String,
)

object SubscriptionSourceLogic {
    fun sourceLabelFor(
        subscriptions: List<SubscriptionSource>,
        url: String,
        emptyLabel: String = "none",
    ): String {
        return subscriptions
            .firstOrNull { it.url == url }
            ?.customName
            ?.takeIf(String::isNotBlank)
            ?: url.takeIf(String::isNotBlank)
                ?.substringAfter("://")
                ?.substringBefore('/')
            ?: emptyLabel
    }

    fun activateSubscription(
        state: MainUiState,
        targetId: String,
    ): SubscriptionSavePlan? {
        if (targetId == ALL_SUBSCRIPTIONS_ID) {
            return SubscriptionSavePlan(
                nextState = state.copy(
                    activeSubscriptionId = targetId,
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    profileUrl = state.profileUrl,
                ),
                statusMessage = SubscriptionStatusMessages.activatedAllSubscriptions(),
            )
        }
        val target = state.subscriptions.firstOrNull { it.id == targetId } ?: return null
        return SubscriptionSavePlan(
            nextState = state.copy(
                activeSubscriptionId = target.id,
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                profileUrl = target.url,
            ),
            statusMessage = SubscriptionStatusMessages.activatedSubscription(sourceLabelFor(state.subscriptions, target.url)),
        )
    }

    fun setSourceMode(
        state: MainUiState,
        mode: ProfileSourceMode,
    ): SubscriptionSavePlan {
        return SubscriptionSavePlan(
            nextState = state.copy(profileSourceMode = mode),
            statusMessage = SubscriptionStatusMessages.profileSourceMode(mode),
        )
    }

    fun showRenameDialog(
        state: MainUiState,
        subscriptionId: String,
    ): MainUiState? {
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId } ?: return null
        return state.copy(
            showProfileHistoryRenameDialog = true,
            profileHistoryRenameSource = target.url,
            profileHistoryRenameUrlDraft = target.url,
            profileHistoryRenameDraft = target.customName,
        )
    }

    fun closeRenameDialog(state: MainUiState): MainUiState {
        return state.copy(
            showProfileHistoryRenameDialog = false,
            profileHistoryRenameSource = "",
            profileHistoryRenameUrlDraft = "",
            profileHistoryRenameDraft = "",
        )
    }

    fun updateRenameDraft(state: MainUiState, value: String): MainUiState {
        return state.copy(profileHistoryRenameDraft = value.take(80))
    }

    fun updateRenameUrlDraft(state: MainUiState, value: String): MainUiState {
        return state.copy(profileHistoryRenameUrlDraft = value.take(4096))
    }

    fun saveRename(
        state: MainUiState,
        validateSubscription: (String) -> Result<Unit>,
    ): Result<SubscriptionRenamePlan> = runCatching {
        val source = state.profileHistoryRenameSource.trim()
        require(source.isNotBlank()) { SubscriptionStatusMessages.invalidSubscriptionUrl() }
        val target = state.subscriptions.firstOrNull { it.url == source }
        require(target != null) { SubscriptionStatusMessages.invalidSubscriptionUrl() }
        val normalizedSource = state.profileHistoryRenameUrlDraft.trim()
        val validation = MainCommandLogic.validateProfileSourceSave(
            value = normalizedSource,
            mode = ProfileSourceMode.SUBSCRIPTION,
            validateSubscription = validateSubscription,
        )
        validation.getOrThrow()
        require(
            state.subscriptions.none { subscription ->
                subscription.id != target.id && subscription.url == normalizedSource
            },
        ) {
            SubscriptionStatusMessages.invalidSubscriptionUrl()
        }

        val normalizedName = state.profileHistoryRenameDraft.trim()
        val sourceChanged = normalizedSource != source
        val updatedSubscriptions = state.subscriptions.map { subscription ->
            if (subscription.id == target.id) {
                subscription.copy(
                    url = normalizedSource,
                    customName = normalizedName,
                    cachedLocations = if (sourceChanged) emptyList() else subscription.cachedLocations,
                    lastRefreshedAtEpochMillis = if (sourceChanged) 0L else subscription.lastRefreshedAtEpochMillis,
                    lastRefreshStatus = if (sourceChanged) "" else subscription.lastRefreshStatus,
                )
            } else {
                subscription
            }
        }
        val nextActiveId = state.activeSubscriptionId
        val nextProfileUrl = when {
            nextActiveId == target.id -> normalizedSource
            isAllSubscriptionsGroupActive(nextActiveId, updatedSubscriptions) -> ""
            else -> state.profileUrl
        }
        val clearSelection = sourceChanged && state.selectedProfileSourceUrl == source
        SubscriptionRenamePlan(
            source = source,
            normalizedSource = normalizedSource,
            normalizedName = normalizedName,
            sourceChanged = sourceChanged,
            nextState = state.copy(
                subscriptions = updatedSubscriptions,
                profileUrl = nextProfileUrl,
                profileDraft = if (state.profileDraft.trim() == source) normalizedSource else state.profileDraft,
                profileHistoryNames = updatedSubscriptions.mapNotNull { subscription ->
                    subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                }.toMap(),
                showProfileHistoryRenameDialog = false,
                profileHistoryRenameSource = "",
                profileHistoryRenameUrlDraft = "",
                profileHistoryRenameDraft = "",
            ).clearSelectedLocationIfNeeded(clearSelection),
            statusMessage = when {
                sourceChanged -> SubscriptionStatusMessages.subscriptionSaved()
                normalizedName.isBlank() -> SubscriptionStatusMessages.subscriptionNameReset()
                else -> SubscriptionStatusMessages.subscriptionNameSaved()
            },
        )
    }

    fun saveSubscriptionDraft(
        state: MainUiState,
        validateSubscription: (String) -> Result<Unit>,
        idGenerator: () -> String,
    ): Result<SubscriptionSavePlan> {
        val trimmed = state.profileDraft.trim()
        val validation = MainCommandLogic.validateProfileSourceSave(
            value = trimmed,
            mode = ProfileSourceMode.SUBSCRIPTION,
            validateSubscription = validateSubscription,
        )
        if (validation.isFailure) {
            return Result.failure(validation.exceptionOrNull() ?: IllegalStateException("Invalid subscription URL"))
        }

        val existingIndex = state.subscriptions.indexOfFirst { it.url == trimmed }
        val existing = state.subscriptions.getOrNull(existingIndex)
        val normalizedName = state.profileTitleDraft.trim()
        val target = (existing ?: SubscriptionSource(
            id = idGenerator(),
            url = trimmed,
            customName = normalizedName.ifBlank { state.profileHistoryNames[trimmed].orEmpty() },
        )).copy(
            customName = normalizedName.ifBlank {
                existing?.customName ?: state.profileHistoryNames[trimmed].orEmpty()
            },
        )
        val updatedSubscriptions = buildList {
            add(target)
            state.subscriptions.forEachIndexed { index, subscription ->
                if (index != existingIndex) {
                    add(subscription)
                }
            }
        }
        return Result.success(
            SubscriptionSavePlan(
                nextState = state.copy(
                    profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                    activeSubscriptionId = target.id,
                    profileUrl = target.url,
                    subscriptions = updatedSubscriptions,
                    profileDraft = target.url,
                    profileTitleDraft = "",
                    showAddSubscriptionEditor = false,
                ),
                statusMessage = validation.getOrThrow(),
            ),
        )
    }

    fun deleteSubscription(
        state: MainUiState,
        subscriptionId: String,
        selectedRawPresentAfterDelete: Boolean,
    ): SubscriptionDeletePlan? {
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId } ?: return null
        val nextSubscriptions = state.subscriptions.filterNot { it.id == subscriptionId }
        val removedSelected = state.selectedProfileSourceUrl == target.url ||
            (state.selectedProfileRawLink.isNotBlank() && !selectedRawPresentAfterDelete)
        val nextActiveId = when {
            nextSubscriptions.isEmpty() -> ""
            isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions) &&
                nextSubscriptions.size > 1 -> ALL_SUBSCRIPTIONS_ID
            state.activeSubscriptionId == subscriptionId -> nextSubscriptions.first().id
            else -> state.activeSubscriptionId
        }
        return SubscriptionDeletePlan(
            target = target,
            removedSelected = removedSelected,
            nextState = state.clearSelectedLocationIfNeeded(removedSelected).copy(
                subscriptions = nextSubscriptions,
                activeSubscriptionId = nextActiveId,
                profileUrl = when {
                    nextActiveId.isBlank() -> ""
                    isAllSubscriptionsGroupActive(nextActiveId, nextSubscriptions) -> ""
                    else -> nextSubscriptions.firstOrNull { it.id == nextActiveId }?.url.orEmpty()
                },
                profileDraft = if (state.profileDraft.trim() == target.url) "" else state.profileDraft,
                profileTitleDraft = if (state.profileDraft.trim() == target.url) "" else state.profileTitleDraft,
                showAddSubscriptionEditor = if (state.profileDraft.trim() == target.url) {
                    false
                } else {
                    state.showAddSubscriptionEditor
                },
            ),
            statusMessage = SubscriptionStatusMessages.subscriptionDeleted(),
        )
    }

    private fun MainUiState.clearSelectedLocationIfNeeded(shouldClear: Boolean): MainUiState {
        if (!shouldClear) return this
        return copy(
            selectedProfileName = "",
            selectedProfileServer = "",
            selectedProfileRawLink = "",
            selectedProfileSourceUrl = "",
        )
    }
}
