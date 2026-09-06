package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.IncomingImportPayload
import com.kardinal.vpncontrol.data.IncomingImportResolver
import com.kardinal.vpncontrol.data.RemoteSourceResolver
import com.kardinal.vpncontrol.model.ProfileSourceMode

internal class AndroidProfileActionsService(
    private val controller: MainController,
    private val stateProvider: () -> MainUiState,
    private val effectSink: AndroidControllerEffectSink,
    private val launch: (suspend () -> Unit) -> Unit,
    private val updateStatus: suspend (String) -> Unit,
    private val launchMutation: (suspend () -> Unit) -> Unit = launch,
    private val sourcePreviewTitle: (String) -> String? = { source ->
        RemoteSourceResolver.preview(source)?.title
    },
    private val validateProfileSource: (String) -> Result<Unit> = RemoteSourceResolver::validateProfileSource,
    private val resolveIncomingImport: suspend (
        raw: String,
        preference: ImportPreference,
        validateSubscription: (String) -> Result<Unit>,
    ) -> Result<IncomingImportPayload> = { raw, preference, validateSubscription ->
        IncomingImportResolver.resolve(
            raw = raw,
            preference = preference,
            validateSubscription = validateSubscription,
        )
    },
) {
    fun onProfileDraftChanged(value: String) {
        controller.onProfileDraftChanged(value)
    }

    fun onProfileTitleDraftChanged(value: String) {
        controller.onProfileTitleDraftChanged(value)
    }

    fun pasteSubscriptionDraft(raw: String) {
        effectSink.handle(controller.pasteSubscriptionDraft(raw))
    }

    fun toggleAddSubscriptionEditor() {
        controller.toggleAddSubscriptionEditor()
    }

    fun showProfileHistoryRenameDialog(source: String) {
        val normalized = source.trim()
        val currentName = stateProvider().profileHistoryNames[normalized]
            ?.takeIf { it.isNotBlank() }
            ?: sourcePreviewTitle(normalized)
                .orEmpty()
        controller.showProfileHistoryRenameDialog(normalized, currentName)
    }

    fun closeProfileHistoryRenameDialog() {
        controller.closeProfileHistoryRenameDialog()
    }

    fun onProfileHistoryRenameDraftChanged(value: String) {
        controller.onProfileHistoryRenameDraftChanged(value)
    }

    fun onProfileHistoryRenameUrlDraftChanged(value: String) {
        controller.onProfileHistoryRenameUrlDraftChanged(value)
    }

    fun setProfileSourceMode(value: ProfileSourceMode) {
        launchMutation { effectSink.handleWithinMutation(controller.setProfileSourceMode(value)) }
    }

    fun saveProfile() {
        launchMutation { effectSink.handleWithinMutation(controller.saveProfile(validateProfileSource)) }
    }

    fun clearProfileSource() {
        controller.clearProfileSource()
    }

    fun handleIncomingSharedText(raw: String) {
        handleIncomingImportText(raw, ImportPreference.AUTO)
    }

    fun handleIncomingImportText(raw: String, preference: ImportPreference = ImportPreference.AUTO) {
        val trimmed = raw.trim()
        if (trimmed.isBlank()) return
        launchMutation {
            resolveIncomingImport(
                trimmed,
                preference,
                validateProfileSource,
            ).fold(
                onSuccess = { payload ->
                    effectSink.handleWithinMutation(controller.handleIncomingImport(payload, preference))
                },
                onFailure = { error ->
                    updateStatus(error.message ?: SubscriptionStatusMessages.sharedTextUnsupportedImport())
                },
            )
        }
    }

    fun useProfileHistoryEntry(subscriptionId: String) {
        launchMutation { effectSink.handleWithinMutation(controller.useProfileHistoryEntry(subscriptionId)) }
    }

    fun deleteProfileHistoryEntry(source: String) {
        launchMutation { effectSink.handleWithinMutation(controller.deleteProfileHistoryEntry(source)) }
    }

    fun saveProfileHistoryRename() {
        launchMutation { effectSink.handleWithinMutation(controller.saveProfileHistoryRename(validateProfileSource)) }
    }
}
