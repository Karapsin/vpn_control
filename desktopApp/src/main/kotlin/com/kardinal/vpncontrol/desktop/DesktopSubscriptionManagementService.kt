package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionSourceLogic
import com.kardinal.vpncontrol.model.ProfileSourceMode
import java.util.UUID

internal class DesktopSubscriptionManagementService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val validateSubscriptionSource: (String) -> Result<Unit>,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val activeConnectionName: () -> String,
    private val commitState: (MainUiState, List<DesktopLocationRecord>) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
) {
    fun sourceLabelFor(url: String): String {
        return SubscriptionSourceLogic.sourceLabelFor(stateProvider().subscriptions, url)
    }

    fun activateSelection(targetId: String) {
        val plan = SubscriptionSourceLogic.activateSubscription(stateProvider(), targetId) ?: return
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    fun setSourceMode(mode: ProfileSourceMode) {
        val plan = SubscriptionSourceLogic.setSourceMode(stateProvider(), mode)
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    fun toggleAddSubscriptionEditor() {
        updateState { current ->
            current.copy(
                showAddSubscriptionEditor = !current.showAddSubscriptionEditor,
                profileDraft = if (current.showAddSubscriptionEditor) current.profileDraft else current.profileUrl,
            )
        }
    }

    fun setProfileDraft(value: String) {
        updateState { it.copy(profileDraft = value) }
    }

    fun clearProfileDraft() {
        updateState { it.copy(profileDraft = "") }
    }

    fun showSubscriptionRenameDialog(subscriptionId: String) {
        val next = SubscriptionSourceLogic.showRenameDialog(stateProvider(), subscriptionId) ?: return
        updateState { next }
    }

    fun closeSubscriptionRenameDialog() {
        updateState(SubscriptionSourceLogic::closeRenameDialog)
    }

    fun setSubscriptionRenameDraft(value: String) {
        updateState { SubscriptionSourceLogic.updateRenameDraft(it, value) }
    }

    fun saveSubscriptionRename() {
        val plan = SubscriptionSourceLogic.saveRename(stateProvider())
        if (plan == null) {
            closeSubscriptionRenameDialog()
            return
        }
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    fun saveSubscriptionDraft() {
        val result = SubscriptionSourceLogic.saveSubscriptionDraft(
            state = stateProvider(),
            validateSubscription = validateSubscriptionSource,
            idGenerator = idGenerator,
        )
        if (result.isFailure) {
            updateState {
                it.withStatus(result.exceptionOrNull()?.message ?: "Invalid subscription URL")
            }
            return
        }
        val plan = result.getOrThrow()
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    suspend fun deleteSubscription(subscriptionId: String) {
        val state = stateProvider()
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId } ?: return
        val nextLocations = locationsProvider().filterNot { it.sourceUrl == target.url }
        val plan = SubscriptionSourceLogic.deleteSubscription(
            state = state,
            subscriptionId = subscriptionId,
            selectedRawPresentAfterDelete = state.selectedProfileRawLink.isNotBlank() &&
                nextLocations.any { it.rawLink == state.selectedProfileRawLink },
        ) ?: return

        if (plan.removedSelected && state.isVpnRunning) {
            val stopResult = stopConnection(
                "${activeConnectionName()} stopped. Deleted subscription removed the selected location.",
            )
            if (stopResult.isFailure) {
                return
            }
        }

        val latestState = stateProvider()
        commitState(
            plan.nextState.copy(
                isBusy = latestState.isBusy,
                isRefreshing = latestState.isRefreshing,
                isVpnRunning = latestState.isVpnRunning,
                hasVpnPermission = latestState.hasVpnPermission,
            ).withStatus(plan.statusMessage),
            nextLocations,
        )
    }
}
