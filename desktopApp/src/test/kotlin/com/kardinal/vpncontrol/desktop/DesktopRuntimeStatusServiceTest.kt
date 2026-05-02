package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
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
                StatusMessages.runtimeMode(AppMode.PROXY_ONLY.name),
                StatusMessages.localProxy("127.0.0.1:2080"),
                StatusMessages.runtimeLog("/tmp/current.log"),
            ),
            details,
        )
    }

    @Test
    fun vpnModeWithoutPreflightIncludesCapabilityStatus() {
        val details = service(
            state = MainUiState(appMode = AppMode.VPN),
            desktopVpnCapabilityStatus = { StatusMessages.desktopVpnCapabilityReady() },
        ).details()

        assertEquals(StatusMessageKey.RUNTIME_MODE, StatusMessages.decode(details[0])?.key)
        assertEquals(StatusMessageKey.DESKTOP_VPN_CAPABILITY_READY, StatusMessages.decode(details[1])?.key)
        assertEquals(StatusMessageKey.RUNTIME_LOG, StatusMessages.decode(details[2])?.key)
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

        assertEquals(StatusMessageKey.PREFLIGHT_FAILED, StatusMessages.decode(details[1])?.key)
        assertEquals("fail first: broken first", details[2])
        assertEquals("fail second: broken second", details[3])
        assertEquals(StatusMessageKey.RUNTIME_LOG, StatusMessages.decode(details[4])?.key)
        assertEquals(5, details.size)
    }

    private fun service(
        state: MainUiState,
        currentMode: () -> AppMode? = { null },
        currentPort: () -> Int? = { null },
        lastPreflightReport: () -> DesktopPreflightReport? = { null },
        desktopVpnCapabilityStatus: () -> String = { StatusMessages.desktopVpnCapabilityError("not ready") },
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
