package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopLinuxProcessAdmissionTest {
    @Test fun boundedControlUsesRetainedAdmissionWithoutOpeningOrdinaryPath() {
        var closed = 0
        var release: (() -> Unit)? = null
        var observed = false
        DesktopLinuxProcessAdmission.install(true, { "/opt/vpn-control/bin/vpn-control" },
            enter = { error("ordinary gate path") }, retainUntilExit = { release = it },
            allowPendingControl = true, onPendingControl = { observed = true },
            enterControl = { observed = true; AutoCloseable { closed++ } })
        assertTrue(observed)
        assertEquals(0, closed)
        requireNotNull(release).invoke(); requireNotNull(release).invoke()
        assertEquals(1, closed)
    }

    @Test fun installedLauncherRetainsLeaseUntilShutdownExactlyOnce() {
        var closed = 0
        var release: (() -> Unit)? = null
        DesktopLinuxProcessAdmission.install(true, { "/opt/vpn-control/bin/vpn-control" },
            { AutoCloseable { closed++ } }, { release = it })
        assertEquals(0, closed)
        requireNotNull(release).invoke(); requireNotNull(release).invoke()
        assertEquals(1, closed)
    }

    @Test fun developmentJvmAndNonLinuxNeverOpenGate() {
        DesktopLinuxProcessAdmission.install(true, { "/jdk/bin/java" }, { error("gate") }, { error("hook") })
        DesktopLinuxProcessAdmission.install(false, { error("identity") }, { error("gate") }, { error("hook") })
    }

    @Test fun unknownImageAndBusyGatePreventStartup() {
        for (image in listOf(null, "/opt/other", "/opt/vpn-control")) {
            assertFails { DesktopLinuxProcessAdmission.install(true, { image }, { error("BUSY") }, { error("hook") }) }
        }
    }

    @Test fun shutdownHookFailureClosesAdmission() {
        var closed = 0
        assertFails { DesktopLinuxProcessAdmission.install(true, { "/opt/vpn-control" },
            { AutoCloseable { closed++ } }, { error("shutdown") }) }
        assertEquals(1, closed)
    }
}
