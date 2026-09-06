package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SubscriptionSourceLogic
import com.kardinal.vpncontrol.model.ProfileSourceMode
import java.util.UUID

internal class DesktopSubscriptionManagementService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val validateSubscriptionSource: (String) -> Result<Unit>,
    private val stopConnection: suspend (String?) -> Result<Unit>,
    private val commitState: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit>,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val idGenerator: () -> String = { UUID.randomUUID().toString() },
    private val activeSource: () -> String? = { stateProvider().selectedProfileSourceUrl },
    private val captureRestore: () -> (suspend () -> Result<Unit>) = {
        { Result.failure(IllegalStateException("ROLLBACK_FAILED")) }
    },
) {
    fun sourceLabelFor(url: String): String {
        return SubscriptionSourceLogic.sourceLabelFor(stateProvider().subscriptions, url)
    }

    /** Apply a terminal edit using the GUI's domain plans without borrowing its open drafts. */
    fun saveSubscription(source: String?, name: String?, id: String?): Result<String> {
        val current = stateProvider()
        if (current.isBusy) return Result.failure(IllegalStateException("BUSY"))
        val target = id?.let { key -> current.subscriptions.firstOrNull { it.id == key } }
        if (id != null && target == null) return Result.failure(IllegalArgumentException("NOT_FOUND"))
        val next: MainUiState
        val locations: List<DesktopLocationRecord>
        val savedId: String
        if (target == null) {
            val plan = SubscriptionSourceLogic.saveSubscriptionDraft(
                current.copy(profileDraft = source.orEmpty(), profileTitleDraft = name.orEmpty().take(80)),
                validateSubscriptionSource, idGenerator,
            ).getOrElse { return Result.failure(IllegalArgumentException("INVALID_ARGUMENT")) }
            next = plan.nextState.withStatus(plan.statusMessage)
            locations = locationsProvider()
            savedId = next.activeSubscriptionId
        } else {
            val plan = SubscriptionSourceLogic.saveRename(current.copy(
                profileHistoryRenameSource = target.url,
                profileHistoryRenameUrlDraft = source ?: target.url,
                profileHistoryRenameDraft = (name ?: target.customName).take(80),
            ), validateSubscriptionSource).getOrElse { return Result.failure(IllegalArgumentException("INVALID_ARGUMENT")) }
            next = plan.nextState.withStatus(plan.statusMessage)
            locations = if (plan.sourceChanged) locationsProvider().filterNot { it.sourceUrl == plan.source } else locationsProvider()
            savedId = target.id
        }
        return commitState(next.copy(
            profileDraft = current.profileDraft,
            profileTitleDraft = current.profileTitleDraft,
            showAddSubscriptionEditor = current.showAddSubscriptionEditor,
            showProfileHistoryRenameDialog = current.showProfileHistoryRenameDialog,
            profileHistoryRenameSource = current.profileHistoryRenameSource,
            profileHistoryRenameUrlDraft = current.profileHistoryRenameUrlDraft,
            profileHistoryRenameDraft = current.profileHistoryRenameDraft,
        ), locations).map { savedId }
    }

    fun activateSelection(targetId: String): Result<Unit> {
        val plan = SubscriptionSourceLogic.activateSubscription(stateProvider(), targetId)
            ?: return Result.failure(IllegalArgumentException("NOT_FOUND"))
        return commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    fun setSourceMode(mode: ProfileSourceMode): Result<Unit> {
        val plan = SubscriptionSourceLogic.setSourceMode(stateProvider(), mode)
        return commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    fun toggleAddSubscriptionEditor() {
        updateState { current ->
            current.copy(
                showAddSubscriptionEditor = !current.showAddSubscriptionEditor,
                profileDraft = if (current.showAddSubscriptionEditor) current.profileDraft else current.profileUrl,
                profileTitleDraft = "",
            )
        }
    }

    fun setProfileDraft(value: String) {
        updateState { it.copy(profileDraft = value) }
    }

    fun setProfileTitleDraft(value: String) {
        updateState { it.copy(profileTitleDraft = value.take(80)) }
    }

    fun clearProfileDraft() {
        updateState { it.copy(profileDraft = "", profileTitleDraft = "") }
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

    fun setSubscriptionRenameUrlDraft(value: String) {
        updateState { SubscriptionSourceLogic.updateRenameUrlDraft(it, value) }
    }

    fun saveSubscriptionRename() {
        val result = SubscriptionSourceLogic.saveRename(stateProvider(), validateSubscriptionSource)
        if (result.isFailure) {
            updateState {
                it.withStatus(result.exceptionOrNull()?.message ?: SubscriptionStatusMessages.invalidSubscriptionUrl())
            }
            return
        }
        val plan = result.getOrThrow()
        val nextLocations = if (plan.sourceChanged) {
            locationsProvider().filterNot { it.sourceUrl == plan.source }
        } else {
            locationsProvider()
        }
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            nextLocations,
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
                it.withStatus(result.exceptionOrNull()?.message ?: SubscriptionStatusMessages.invalidSubscriptionUrl())
            }
            return
        }
        val plan = result.getOrThrow()
        commitState(
            plan.nextState.withStatus(plan.statusMessage),
            locationsProvider(),
        )
    }

    suspend fun deleteSubscription(subscriptionId: String,
        validateAdmission: () -> Result<Unit> = { Result.success(Unit) },
        guardedCommit: (MainUiState, List<DesktopLocationRecord>) -> Result<Unit> = commitState,
        captureRestoreAction: () -> (suspend () -> Result<Unit>) = captureRestore,
    ): Result<Unit> {
        validateAdmission().getOrElse { return Result.failure(it) }
        val state = stateProvider()
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        val target = state.subscriptions.firstOrNull { it.id == subscriptionId }
            ?: return Result.failure(IllegalArgumentException("NOT_FOUND"))
        val nextLocations = locationsProvider().filterNot { it.sourceUrl == target.url }
        val plan = SubscriptionSourceLogic.deleteSubscription(
            state = state,
            subscriptionId = subscriptionId,
            selectedRawPresentAfterDelete = state.selectedProfileRawLink.isNotBlank() &&
                nextLocations.any { it.rawLink == state.selectedProfileRawLink },
        ) ?: return Result.failure(IllegalArgumentException("NOT_FOUND"))

        return commitDesktopRuntimeMutation(
            stopRequired = activeSource() == target.url && state.isVpnRunning,
            captureRestore = captureRestoreAction,
            stop = { stopConnection(
                SubscriptionStatusMessages.subscriptionDeleteRemovedSelectedStopped(state.appMode),
            ) },
            commit = {
                val latestState = stateProvider()
                guardedCommit(
                    plan.nextState.copy(
                        isBusy = latestState.isBusy,
                        isRefreshing = latestState.isRefreshing,
                        isVpnRunning = latestState.isVpnRunning,
                        hasVpnPermission = latestState.hasVpnPermission,
                    ).withStatus(plan.statusMessage),
                    nextLocations,
                )
            },
        )
    }
}
