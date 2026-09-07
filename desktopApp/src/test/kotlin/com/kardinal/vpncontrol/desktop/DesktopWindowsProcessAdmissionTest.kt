package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopWindowsProcessAdmissionTest {
    @Test fun bothPublicLaunchersRetainLeaseUntilProcessExitNotMainReturn() {
        for (name in listOf("vpn-control.exe", "vpn-control-cli.exe")) {
            var closed = 0
            var release: (() -> Unit)? = null
            DesktopWindowsProcessAdmission.install(true, { "C:\\Apps\\東京\\$name" }, {
                assertTrue(it.toString().endsWith(name))
                AutoCloseable { closed++ }
            }, { release = it })
            assertEquals(0, closed)
            requireNotNull(release).invoke()
            requireNotNull(release).invoke()
            assertEquals(1, closed)
        }
    }

    @Test fun developmentJvmAndOtherPlatformsNeverOpenGateOrRegisterHook() {
        for (name in listOf("java.exe", "javaw.exe")) {
            DesktopWindowsProcessAdmission.install(true, { "C:\\JDK\\$name" }, { error("gate") }, { error("hook") })
        }
        DesktopWindowsProcessAdmission.install(false, { error("identity") }, { error("gate") }, { error("hook") })
    }

    @Test fun deniedAdmissionAndUnknownImagePreventSubsequentStartupEffects() {
        var effects = 0
        for (image in listOf(null, "C:\\Apps\\other.exe", "C:\\Apps\\vpn-control-cli.exe")) {
            assertFails {
                DesktopWindowsProcessAdmission.install(true, { image }, { error("BUSY") }, { error("hook") })
                effects++
            }
        }
        assertEquals(0, effects)
    }

    @Test fun failedShutdownRegistrationReleasesAcquiredLease() {
        var closed = 0
        assertFails {
            DesktopWindowsProcessAdmission.install(true, { "C:\\Apps\\vpn-control.exe" },
                { AutoCloseable { closed++ } }, { error("shutdown underway") })
        }
        assertEquals(1, closed)
    }
}
