package com.kardinal.vpncontrol.desktop

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/** Completes an in-flight runtime mutation or restores its captured state before cancellation. */
internal suspend fun commitDesktopRuntimeMutation(
    stopRequired: Boolean,
    captureRestore: () -> (suspend () -> Result<Unit>),
    stop: suspend () -> Result<Unit>,
    commit: () -> Result<Unit>,
): Result<Unit> = withContext(NonCancellable) {
    if (!stopRequired) return@withContext commit()
    val restore = captureRestore()
    val result = runCatching { stop().getOrThrow(); commit().getOrThrow() }
    if (result.isSuccess) return@withContext result
    val rollback = runCatching { restore().getOrThrow() }
    if (rollback.isFailure) Result.failure(IllegalStateException("ROLLBACK_FAILED")) else result
}
