package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.application
import kotlin.system.exitProcess

/** Product frontend application boundary; its exit policy is part of frontend teardown semantics. */
internal fun runDesktopFrontendApplication(content: @Composable ApplicationScope.() -> Unit) {
    // Main must detach the frontend and release its endpoint before the JVM exits.
    application(exitProcessOnExit = false, content = content)
}

/** Runs the frontend as a process boundary: cleanup finishes before this frontend JVM terminates. */
internal fun runDesktopFrontendProcess(content: @Composable ApplicationScope.() -> Unit, teardown: () -> Unit) {
    finishDesktopFrontendProcess({ runDesktopFrontendApplication(content) }, teardown)
}

/** Pure lifecycle ordering behind the product process boundary. */
internal fun finishDesktopFrontendProcess(
    runFrontend: () -> Unit,
    teardown: () -> Unit,
    reportFailure: (Throwable) -> Unit = { it.printStackTrace(System.err) },
    terminate: (Int) -> Unit = ::exitProcess,
) {
    var failure: Throwable? = null
    try {
        runFrontend()
    } catch (error: Throwable) {
        failure = error
    }
    try {
        teardown()
    } catch (error: Throwable) {
        failure?.addSuppressed(error) ?: run { failure = error }
    }
    val terminalFailure = failure
    if (terminalFailure != null) {
        reportFailure(terminalFailure)
        terminate(1)
        throw terminalFailure
    }
    terminate(0)
}
