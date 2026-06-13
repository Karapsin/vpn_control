package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopRuntimeStatusServiceTest {
    private val defaultLogPath = Paths.get("tmp", "default.log")

    @Test
    fun proxyModeDetailsIncludeRuntimeModePortAndLog() {
        val currentLogPath = Paths.get("tmp", "current.log")
        val details = service(
            state = MainUiState(appMode = AppMode.PROXY_ONLY),
            currentMode = { AppMode.PROXY_ONLY },
            currentPort = { 2080 },
            currentLogFile = { currentLogPath },
        ).details()

        assertEquals(
            listOf(
                RuntimeStatusMessages.runtimeMode(AppMode.PROXY_ONLY.name),
                RuntimeStatusMessages.localProxy("127.0.0.1:2080"),
                RuntimeStatusMessages.runtimeLog(currentLogPath.toString()),
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
        assertEquals(RuntimeStatusMessages.runtimeLog(defaultLogPath.toString()), details[2])
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
        assertEquals(RuntimeStatusMessages.runtimeLog(defaultLogPath.toString()), details[4])
        assertEquals(5, details.size)
    }

    @Test
    fun runningDetailsIncludeRedactedOutboundTimeoutHint() {
        val logFile = Files.createTempFile("vpn-control-runtime-status", ".log")
        try {
            Files.writeString(
                logFile,
                listOf(
                    "INFO inbound/tun[tun-in]: inbound connection",
                    "ERROR connection using outbound/vless[proxy]: dial tcp 203.0.113.10:8443: i/o timeout",
                    "ERROR connection using outbound/vless[proxy]: read: connection timed out",
                    "ERROR connection using outbound/vless[proxy]: read: connection reset by peer",
                ).joinToString("\n"),
            )

            val details = service(
                state = MainUiState(appMode = AppMode.VPN, isVpnRunning = true),
                currentLogFile = { logFile },
            ).details()

            assertTrue(
                details.contains("Runtime outbound has repeated timeouts or resets; try another location or Find Best."),
            )
            assertEquals(RuntimeStatusMessages.runtimeLog(logFile.toString()), details.last())
        } finally {
            Files.deleteIfExists(logFile)
        }
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
            defaultLogFile = { defaultLogPath },
        )
    }
}
