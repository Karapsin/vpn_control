package com.kardinal.vpncontrol.desktop

/** The adapter supplies retained ownership; no failure message contains native paths or input. */
internal fun desktopWindowsPreparationFailure(
    failure: Throwable,
    stage: DesktopWindowsRuntimePreparationStage,
    abort: () -> Boolean,
    close: () -> Unit,
    unresolved: () -> DesktopRuntimeProcess,
    brokerExit: () -> Int? = { null },
): DesktopWindowsRuntimeFailure {
    val aborted = runCatching(abort).getOrDefault(false)
    // Read after abort, which waits for the broker, and before close, which releases its process handle.
    val exit = if (aborted) runCatching(brokerExit).getOrNull() else null
    if (!aborted || runCatching(close).isFailure)
        return DesktopWindowsRuntimeFailure("OUTCOME_UNKNOWN", unresolved(), stage, brokerExit = exit)
    return when (failure) {
        is DesktopWindowsRuntimeFailure -> failure.withBrokerExit(exit)
        is kotlinx.coroutines.CancellationException -> DesktopWindowsRuntimeFailure("CANCELLED", stage = stage, brokerExit = exit)
        is OutOfMemoryError -> DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED", stage = stage, brokerExit = exit)
        else -> DesktopWindowsRuntimeFailure("UNAVAILABLE", stage = stage, brokerExit = exit)
    }
}

/**
 * The broker's exit codes (VpnBrokerStep in windows-vpn-broker.cs): each names the last step the elevated broker
 * entered before it refused. Diagnostic detail only; the public error code stays what the transition reports.
 */
internal object DesktopWindowsBrokerExit {
    val STEPS: Map<Int, String> = linkedMapOf(
        0 to "success",
        1 to "unclassified",
        10 to "arguments",
        11 to "runtime-authority",
        20 to "owner-open",
        21 to "owner-token",
        22 to "owner-identity",
        23 to "package-admission",
        30 to "pipe-create",
        31 to "pipe-connect",
        32 to "peer",
        33 to "protocol",
        34 to "job",
        35 to "resource-preparation",
        40 to "runtime-image",
        41 to "stage",
        42 to "original-user",
        43 to "configuration",
        44 to "child-create",
        45 to "ready-ack",
        50 to "running",
    )

    fun step(exit: Int): String = STEPS[exit] ?: "unknown"

    /** One log line for a failed scoped start, or null when no broker exit was observed. */
    fun describe(failure: Throwable): String? {
        val native = failure as? DesktopWindowsRuntimeFailure ?: return null
        val exit = native.brokerExit ?: return null
        return "scoped Windows broker ended at step ${step(exit)} (exit $exit, " +
            "stage ${native.stage?.name ?: "unknown"}, code ${native.code})"
    }

    /** Appends [describe]'s line to the candidate runtime log and returns it; a log write failure never hides it. */
    fun record(failure: Throwable, logFile: java.nio.file.Path): String? {
        val line = describe(failure) ?: return null
        runCatching { java.nio.file.Files.writeString(logFile, "vpn-control: $line\n", java.nio.file.StandardOpenOption.APPEND) }
        return line
    }
}
