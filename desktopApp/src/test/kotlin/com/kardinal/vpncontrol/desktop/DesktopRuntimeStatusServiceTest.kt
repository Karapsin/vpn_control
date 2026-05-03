package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopRuntimeStatusServiceTest {
    @Test
    fun proxyModeDetailsIncludeRuntimeModePortAndLog() {
        val details = service(
            state = MainUiState(appMode = AppMode.PROXY_ONLY),
            currentMode = { AppMode.PROXY_ONLY },
            currentPort = { 2080 },
            currentLogFile = { Paths.get("/tmp/current.log") },
        ).details()

        assertEquals(
            listOf(
                RuntimeStatusMessages.runtimeMode(AppMode.PROXY_ONLY.name),
                RuntimeStatusMessages.localProxy("127.0.0.1:2080"),
                RuntimeStatusMessages.runtimeLog("/tmp/current.log"),
            ),
            details,
        )
    }

    @Test
    fun vpnModeWithoutPreflightIncludesCapabilityStatus() {
        val details = service(
            state = MainUiState(appMode = AppMode.VPN),
            desktopVpnCapabilityStatus = { RuntimeStatusMessages.desktopVpnCapabilityReady() },
        ).details()

        assertEquals(RuntimeStatusMessages.runtimeMode(AppMode.VPN.name), details[0])
        assertEquals(RuntimeStatusMessages.desktopVpnCapabilityReady(), details[1])
        assertEquals(RuntimeStatusMessages.runtimeLog("/tmp/default.log"), details[2])
    }

    @Test
    fun vpnModeWithPreflightIncludesSummaryAndTwoFailedChecks() {
        val report = DesktopPreflightReport(
            appMode = AppMode.VPN,
            checks = listOf(
                DesktopPreflightCheck("first", DesktopPreflightStatus.FAIL, "broken first"),
                DesktopPreflightCheck("second", DesktopPreflightStatus.FAIL, "broken second"),
                DesktopPreflightCheck("third", DesktopPreflightStatus.FAIL, "broken third"),
            ),
        )

        val details = service(
            state = MainUiState(appMode = AppMode.VPN),
            lastPreflightReport = { report },
        ).details()

        assertEquals(RuntimeStatusMessages.preflightFailed(AppMode.VPN, failedChecks = 3), details[1])
        assertEquals("fail first: broken first", details[2])
        assertEquals("fail second: broken second", details[3])
        assertEquals(RuntimeStatusMessages.runtimeLog("/tmp/default.log"), details[4])
        assertEquals(5, details.size)
    }

    private fun service(
        state: MainUiState,
        currentMode: () -> AppMode? = { null },
        currentPort: () -> Int? = { null },
        lastPreflightReport: () -> DesktopPreflightReport? = { null },
        desktopVpnCapabilityStatus: () -> String = { RuntimeStatusMessages.desktopVpnCapabilityError("not ready") },
        currentLogFile: () -> java.nio.file.Path? = { null },
    ): DesktopRuntimeStatusService {
        return DesktopRuntimeStatusService(
            stateProvider = { state },
            currentMode = currentMode,
            currentPort = currentPort,
            lastPreflightReport = lastPreflightReport,
            desktopVpnCapabilityStatus = desktopVpnCapabilityStatus,
            currentLogFile = currentLogFile,
            defaultLogFile = { Paths.get("/tmp/default.log") },
        )
    }
}
