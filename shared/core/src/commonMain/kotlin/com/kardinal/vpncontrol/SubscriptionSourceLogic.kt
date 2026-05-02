package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessages
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
                statusMessage = StatusMessages.activatedAllSubscriptions(),
            )
        }
        val target = state.subscriptions.firstOrNull { it.id == targetId } ?: return null
        return SubscriptionSavePlan(
            nextState = state.copy(
                activeSubscriptionId = target.id,
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                profileUrl = target.url,
            ),
            statusMessage = StatusMessages.activatedSubscription(sourceLabelFor(state.subscriptions, target.url)),
        )
    }

    fun setSourceMode(
        state: MainUiState,
        mode: ProfileSourceMode,
    ): SubscriptionSavePlan {
        return SubscriptionSavePlan(
            nextState = state.copy(profileSourceMode = mode),
            statusMessage = StatusMessages.profileSourceMode(mode),
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
            profileHistoryRenameDraft = target.customName,
        )
    }

    fun closeRenameDialog(state: MainUiState): MainUiState {
        return state.copy(
            showProfileHistoryRenameDialog = false,
            profileHistoryRenameSource = "",
            profileHistoryRenameDraft = "",
        )
    }

    fun updateRenameDraft(state: MainUiState, value: String): MainUiState {
        return state.copy(profileHistoryRenameDraft = value.take(80))
    }

    fun saveRename(state: MainUiState): SubscriptionSavePlan? {
        val source = state.profileHistoryRenameSource.trim()
        if (source.isBlank()) return null
        val normalizedName = state.profileHistoryRenameDraft.trim()
        val updatedSubscriptions = state.subscriptions.map { subscription ->
            if (subscription.url == source) {
                subscription.copy(customName = normalizedName)
            } else {
                subscription
            }
        }
        return SubscriptionSavePlan(
            nextState = state.copy(
                subscriptions = updatedSubscriptions,
                showProfileHistoryRenameDialog = false,
                profileHistoryRenameSource = "",
                profileHistoryRenameDraft = "",
            ),
            statusMessage = if (normalizedName.isBlank()) {
                StatusMessages.subscriptionNameReset()
            } else {
                StatusMessages.subscriptionNameSaved()
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
        val target = existing ?: SubscriptionSource(
            id = idGenerator(),
            url = trimmed,
            customName = state.profileHistoryNames[trimmed].orEmpty(),
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
                showAddSubscriptionEditor = if (state.profileDraft.trim() == target.url) {
                    false
                } else {
                    state.showAddSubscriptionEditor
                },
            ),
            statusMessage = StatusMessages.subscriptionDeleted(),
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
