package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopMacProcessAdmissionTest {
    @Test fun admittedProcessRetainsLeaseAndReportsActualPendingUntilShutdown() {
        var closed = 0
        var pending = 0
        var shutdown: (() -> Unit)? = null
        DesktopMacProcessAdmission.install(mac = true,
            executable = { "/Applications/東京 app.app/Contents/MacOS/vpn-control" },
            enter = { _, allow, callback -> assertTrue(allow); callback(); AutoCloseable { closed++ } },
            allowPendingControl = true, onPendingControl = { pending++ }, retainUntilExit = { shutdown = it })
        assertEquals(1, pending)
        assertEquals(0, closed)
        shutdown!!.invoke(); shutdown!!.invoke()
        assertEquals(1, closed)
    }
    @Test fun normalClearAdmissionNeverSelectsPendingRoleAndFailedHookReleasesLease() {
        var closed = 0
        assertFails {
            DesktopMacProcessAdmission.install(mac = true,
                executable = { "/Applications/vpn-control.app/Contents/MacOS/vpn-control" },
                enter = { _, allow, _ -> assertFalse(allow); AutoCloseable { closed++ } },
                onPendingControl = { error("No pending gate") }, retainUntilExit = { error("Shutdown in progress") })
        }
        assertEquals(1, closed)
    }
    @Test fun otherPlatformsAndDevelopmentJvmNeverAcquireNativeGate() {
        DesktopMacProcessAdmission.install(mac = false, executable = { error("Not Darwin") })
        DesktopMacProcessAdmission.install(mac = true, executable = { "/jdk/bin/java" },
            enter = { _, _, _ -> error("Development JVM") }, retainUntilExit = { error("No lease") })
        assertFails { DesktopMacProcessAdmission.install(mac = true, executable = { "/bin/other" },
            enter = { _, _, _ -> error("Unknown image") }) }
    }
}
