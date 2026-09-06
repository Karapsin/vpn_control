package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopRuntimePresentationTest {
    @Test fun routineCaptureNeverScansLogsRunsPreflightOrExportsRawFailures() {
        val service = DesktopRuntimeStatusService(
            stateProvider = { MainUiState(appMode = AppMode.VPN) },
            currentMode = { AppMode.PROXY_ONLY }, currentPort = { 1080 },
            lastPreflightReport = { DesktopPreflightReport(AppMode.VPN, listOf(
                DesktopPreflightCheck("PRIVATE_CHECK", DesktopPreflightStatus.FAIL, "/PRIVATE_PATH PROFILE_SECRET"))) },
            desktopVpnCapabilityStatus = { error("must not probe during routine capture") },
            currentLogFile = { error("must not inspect log paths during routine capture") },
            defaultLogFile = { error("must not read logs during routine capture") },
        )
        val captured = service.presentation()
        assertEquals(AppMode.PROXY_ONLY, captured.mode)
        assertEquals(1080, captured.localProxyPort)
        assertEquals(1, captured.failedPreflightChecks)
        assertFalse(captured.outboundStatusAvailable)
        assertEquals(3, captured.messages().size)
        assertEquals(captured, DesktopRuntimePresentation.decode(captured.values()))
        assertFalse(ControlProtocolCodec.encodeValues(captured.values().values).contains("PRIVATE"))
    }

    @Test fun unavailablePreflightRemainsUnknownAndInvalidPortsCannotBePublished() {
        val empty = DesktopRuntimePresentation(AppMode.VPN, null, null, null)
        assertEquals(empty, DesktopRuntimePresentation.decode(empty.values()))
        assertNull(empty.failedPreflightChecks)
        assertEquals(1, empty.messages().size)
        assertFails { DesktopRuntimePresentation.decode(DesktopRuntimePresentation(AppMode.VPN, 0, null, null).values()) }
        assertFails { DesktopRuntimePresentation.decode(DesktopRuntimePresentation(AppMode.VPN, null, null, 0).values()) }
    }

    @Test fun releaseNotesLinkNeverIncludesCredentialsQueryOrOtherDestinations() {
        val valid = "https://github.com/Karapsin/vpn_control/releases/tag/2.1.0"
        assertEquals(valid, safeDesktopReleaseNotesUrl(valid))
        for (invalid in listOf("", "file:///private", "https://user:secret@github.com/Karapsin/vpn_control/releases/tag/x",
            "$valid?token=secret", "$valid#secret", "https://example.test/private", "https://github.com/other/private"))
            assertNull(safeDesktopReleaseNotesUrl(invalid))
    }
}
