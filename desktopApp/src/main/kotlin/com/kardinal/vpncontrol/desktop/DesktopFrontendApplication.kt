package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.ui.window.ApplicationScope
import androidx.compose.ui.window.application

/** Product frontend application boundary; its exit policy is part of frontend teardown semantics. */
internal fun runDesktopFrontendApplication(content: @Composable ApplicationScope.() -> Unit) {
    // Main must detach the frontend and release its endpoint before the JVM exits.
    application(exitProcessOnExit = false, content = content)
}
