package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessages
import kotlinx.coroutines.delay

enum class SelectionCommitStage {
    SUCCESS,
    APPLY_FAILED,
    PERSIST_FAILED_WITHOUT_APPLY,
    PERSIST_FAILED_AFTER_APPLY,
}

data class SelectionCommitResult(
    val stage: SelectionCommitStage,
    val error: Throwable? = null,
) {
    val isSuccess: Boolean
        get() = stage == SelectionCommitStage.SUCCESS

    val shouldRestoreSnapshot: Boolean
        get() = stage == SelectionCommitStage.APPLY_FAILED ||
            stage == SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY

    val requiresLiveRollback: Boolean
        get() = stage == SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY
}

data class SelectionCommitFailureTexts(
    val applyFailureFallback: String,
    val persistFailureWithoutApplyFallback: String,
    val persistFailureAfterApplyFallback: String,
)

object ConnectionOrchestrationLogic {
    suspend fun <T> findBestProfileWithRetries(
        retryCount: Int,
        onRetryStatus: suspend (String) -> Unit,
        action: suspend () -> Result<T>,
    ): Result<T> {
        val normalizedRetryCount = retryCount.coerceAtLeast(0)
        var lastFailure: Throwable? = null
        repeat(normalizedRetryCount + 1) { attempt ->
            if (attempt > 0) {
                onRetryStatus(
                    StatusMessages.retryingBestLocationSearch(
                        attempt = attempt + 1,
                        total = normalizedRetryCount + 1,
                    ),
                )
                delay(750)
            }
            val result = action()
            if (result.isSuccess) {
                return result
            }
            lastFailure = result.exceptionOrNull()
        }
        return Result.failure(lastFailure ?: IllegalStateException(StatusMessages.locationSearchFailed()))
    }

    fun selectionCommitFailureMessage(
        result: SelectionCommitResult,
        texts: SelectionCommitFailureTexts,
    ): String {
        return when (result.stage) {
            SelectionCommitStage.SUCCESS -> ""
            SelectionCommitStage.APPLY_FAILED ->
                result.error?.message ?: texts.applyFailureFallback
            SelectionCommitStage.PERSIST_FAILED_WITHOUT_APPLY ->
                result.error?.message ?: texts.persistFailureWithoutApplyFallback
            SelectionCommitStage.PERSIST_FAILED_AFTER_APPLY ->
                result.error?.message ?: texts.persistFailureAfterApplyFallback
        }
    }

    fun toggleStartPreconditionError(state: MainUiState): String? {
        return if (state.appMode == AppMode.VPN && !state.hasVpnPermission) {
            StatusMessages.vpnPermissionRequired()
        } else {
            null
        }
    }

    fun preparingConnectionMessage(appMode: AppMode): String {
        return StatusMessages.startingConnection(appMode)
    }

    fun ensureSelectionFailureMessage(appMode: AppMode, errorMessage: String?): String {
        return errorMessage ?: StatusMessages.connectionStartFailed(appMode)
    }

    fun refreshSelectionStartedMessage(appMode: AppMode, remarks: String): String {
        return StatusMessages.connectionStartedOnTarget(appMode, remarks)
    }

    fun refreshCancelledMessage(): String = StatusMessages.locationSearchCancelled()

    fun cancelledWithStopFailureMessage(prefix: String, appMode: AppMode, errorMessage: String?): String {
        return "$prefix ${errorMessage ?: "Failed to stop ${MainCommandLogic.connectionNoun(appMode)}."}"
    }

    fun connectionStartCancelledMessage(appMode: AppMode): String {
        return "${MainCommandLogic.connectionDisplayName(appMode)} start cancelled"
    }

    fun connectionStopCancelledMessage(appMode: AppMode): String {
        return "${MainCommandLogic.connectionDisplayName(appMode)} stop cancelled"
    }

    fun connectionStopFailureMessage(appMode: AppMode, errorMessage: String?): String {
        return errorMessage ?: StatusMessages.connectionStopFailed(appMode)
    }

    fun startSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = StatusMessages.connectionStartFailed(appMode),
            persistFailureWithoutApplyFallback = StatusMessages.selectedLocationSaveFailed(),
            persistFailureAfterApplyFallback = StatusMessages.selectedLocationStartedSaveFailed(appMode),
        )
    }

    fun refreshSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = StatusMessages.bestLocationStartFailed(appMode),
            persistFailureWithoutApplyFallback = StatusMessages.bestLocationSaveFailed(),
            persistFailureAfterApplyFallback = StatusMessages.bestLocationStartedSaveFailed(appMode),
        )
    }
}
