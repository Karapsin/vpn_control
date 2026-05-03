package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
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
                onRetryStatus(
                    BenchmarkStatusMessages.retryingBestLocationSearch(
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
        return Result.failure(lastFailure ?: IllegalStateException(BenchmarkStatusMessages.locationSearchFailed()))
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
            BenchmarkStatusMessages.vpnPermissionRequired()
        } else {
            null
        }
    }

    fun preparingConnectionMessage(appMode: AppMode): String {
        return ConnectionStatusMessages.startingConnection(appMode)
    }

    fun ensureSelectionFailureMessage(appMode: AppMode, errorMessage: String?): String {
        return errorMessage ?: ConnectionStatusMessages.connectionStartFailed(appMode)
    }

    fun refreshSelectionStartedMessage(appMode: AppMode, remarks: String): String {
        return ConnectionStatusMessages.connectionStartedOnTarget(appMode, remarks)
    }

    fun refreshCancelledMessage(): String = BenchmarkStatusMessages.locationSearchCancelled()

    fun cancelledWithStopFailureMessage(prefix: String, appMode: AppMode, errorMessage: String?): String {
        return if (prefix == BenchmarkStatusMessages.locationSearchCancelled()) {
            BenchmarkStatusMessages.locationSearchCancelledStopFailed(appMode, errorMessage.orEmpty())
        } else {
            "$prefix ${errorMessage ?: ConnectionStatusMessages.connectionStopFailed(appMode)}"
        }
    }

    fun connectionStartCancelledMessage(appMode: AppMode): String {
        return ConnectionStatusMessages.connectionStartCancelled(appMode)
    }

    fun connectionStopCancelledMessage(appMode: AppMode): String {
        return ConnectionStatusMessages.connectionStopCancelled(appMode)
    }

    fun connectionStopFailureMessage(appMode: AppMode, errorMessage: String?): String {
        return errorMessage ?: ConnectionStatusMessages.connectionStopFailed(appMode)
    }

    fun startSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = ConnectionStatusMessages.connectionStartFailed(appMode),
            persistFailureWithoutApplyFallback = ConnectionStatusMessages.selectedLocationSaveFailed(),
            persistFailureAfterApplyFallback = ConnectionStatusMessages.selectedLocationStartedSaveFailed(appMode),
        )
    }

    fun refreshSelectionFailureTexts(appMode: AppMode): SelectionCommitFailureTexts {
        return SelectionCommitFailureTexts(
            applyFailureFallback = ConnectionStatusMessages.bestLocationStartFailed(appMode),
            persistFailureWithoutApplyFallback = ConnectionStatusMessages.bestLocationSaveFailed(),
            persistFailureAfterApplyFallback = ConnectionStatusMessages.bestLocationStartedSaveFailed(appMode),
        )
    }
}
