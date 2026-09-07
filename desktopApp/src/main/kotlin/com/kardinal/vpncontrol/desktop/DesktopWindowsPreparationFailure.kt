package com.kardinal.vpncontrol.desktop

/** The adapter supplies retained ownership; no failure message contains native paths or input. */
internal fun desktopWindowsPreparationFailure(
    failure: Throwable,
    stage: DesktopWindowsRuntimePreparationStage,
    abort: () -> Boolean,
    close: () -> Unit,
    unresolved: () -> DesktopRuntimeProcess,
): DesktopWindowsRuntimeFailure {
    if (!runCatching(abort).getOrDefault(false) || runCatching(close).isFailure)
        return DesktopWindowsRuntimeFailure("OUTCOME_UNKNOWN", unresolved(), stage)
    return when (failure) {
        is DesktopWindowsRuntimeFailure -> failure
        is kotlinx.coroutines.CancellationException -> DesktopWindowsRuntimeFailure("CANCELLED", stage = stage)
        is OutOfMemoryError -> DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = stage)
        else -> DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = stage)
    }
}
