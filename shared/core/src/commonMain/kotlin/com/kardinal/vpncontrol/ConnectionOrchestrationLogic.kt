package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
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
                onRetryStatus("Retrying best location search (${attempt + 1}/${normalizedRetryCount + 1})...")
                delay(750)
            }
            val result = action()
            if (result.isSuccess) {
                return result
            }
            lastFailure = result.exceptionOrNull()
        }
        return Result.failure(lastFailure ?: IllegalStateException("Location search failed"))
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
            "Grant VPN permission and try again"
        } else {
            null
        }
    }

    fun preparingConnectionMessage(appMode: AppMode): String {
        return "Preparing ${MainCommandLogic.connectionNoun(appMode)}"
    }

    fun ensureSelectionFailureMessage(appMode: AppMode, errorMessage: String?): String {
        return errorMessage ?: "Could not prepare ${MainCommandLogic.connectionNoun(appMode)}"
    }

    fun refreshSelectionStartedMessage(appMode: AppMode, remarks: String): String {
        return "Best location selected and ${MainCommandLogic.startedConnectionLabel(appMode).lowercase()}: $remarks"
    }

    fun refreshCancelledMessage(): String = "Location search cancelled"

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
        return errorMessage ?: "Failed to stop ${MainCommandLogic.connectionNoun(appMode)}"
    }

    fun startSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = "Failed to start ${MainCommandLogic.connectionNoun(appMode)}",
            persistFailureWithoutApplyFallback = "Failed to save the selected location",
            persistFailureAfterApplyFallback = "${MainCommandLogic.connectionDisplayName(appMode)} started, but failed to save the selected location",
        )
    }

    fun refreshSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = "Failed to start ${MainCommandLogic.connectionNoun(appMode)} with the best location",
            persistFailureWithoutApplyFallback = "Failed to save the best location",
            persistFailureAfterApplyFallback = "Best location ${MainCommandLogic.connectionNoun(appMode)} started, but failed to save it",
        )
    }
}
