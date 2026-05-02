package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopDiagnosticsServiceTest {
    @Test
    fun exportWritesDiagnosticsAndUpdatesStatus() = runTest {
        val tempDir = Files.createTempDirectory("vpn-control-diagnostics-service")
        try {
            val store = DesktopStateStore(tempDir)
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = tempDir.resolve("runtime"),
                singBoxResolver = DesktopSingBoxResolver(
                    toolsDir = tempDir.resolve("tools"),
                    classLoader = javaClass.classLoader,
                ),
            )
            var state = MainUiState(statusMessage = "Ready")
            val service = DesktopDiagnosticsService(
                stateProvider = { state },
                desktopStore = store,
                runtimeManager = runtimeManager,
                updateState = { transform -> state = transform(state) },
            )
            val target = tempDir.resolve("diagnostics.txt")

            service.export(Result.success(target))

            val report = Files.readString(target)
            assertTrue(report.contains("VPN Control Desktop Diagnostics"))
            assertTrue(report.contains("status=Ready"))
            assertTrue(state.statusMessage.contains("Diagnostics exported to"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun exportCancellationUpdatesStatusWithoutWritingFile() = runTest {
        var state = MainUiState()
        val tempDir = Files.createTempDirectory("vpn-control-diagnostics-cancel")
        try {
            val store = DesktopStateStore(tempDir)
            val runtimeManager = DesktopProxyRuntimeManager(
                runtimeConfigStore = store,
                baseDir = tempDir.resolve("runtime"),
                singBoxResolver = DesktopSingBoxResolver(
                    toolsDir = tempDir.resolve("tools"),
                    classLoader = javaClass.classLoader,
                ),
            )
            val service = DesktopDiagnosticsService(
                stateProvider = { state },
                desktopStore = store,
                runtimeManager = runtimeManager,
                updateState = { transform -> state = transform(state) },
            )

            service.export(Result.success(null))

            assertTrue(state.statusMessage.contains("Diagnostics export canceled"))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
