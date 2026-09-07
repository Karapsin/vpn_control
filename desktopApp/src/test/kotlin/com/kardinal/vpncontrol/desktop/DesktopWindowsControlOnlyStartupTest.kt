package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopWindowsControlOnlyStartupTest {
    @Test fun pendingInspectionKeepsSharedLockAndPinsUntilProcessExit() {
        val fake = DesktopWindowsInstallAdmissionTest.Fake().apply { bytes[8] = 1 }
        var release: (() -> Unit)? = null
        DesktopWindowsProcessAdmission.install(true, { "C:\\Apps\\vpn-control-cli.exe" },
            retainUntilExit = { release = it }, allowPendingControl = true,
            enterControl = { DesktopWindowsInstallAdmission.enter(it, fake, allowPendingControl = true) })
        assertTrue("lock" in fake.events)
        assertTrue(fake.handles.none { it.closed })
        release!!.invoke()
        assertTrue(fake.handles.all { it.closed })
        val exclusive = DesktopWindowsInstallAdmissionTest.Fake().apply { bytes[8] = 1; lockAvailable = false }
        assertEquals("BUSY", assertFails { DesktopWindowsInstallAdmission.enter(Path.of("C:\\Apps\\vpn-control-cli.exe"),
            exclusive, allowPendingControl = true) }.message)
    }

    @Test fun onlyStrictBoundedControlCommandsBypassPendingAndNeverBootstrap() {
        for (args in listOf(listOf("status"), listOf("--json", "updates", "status"),
            listOf("operations", "list"), listOf("operations", "status", "opaque"), listOf("operations", "cancel", "opaque"))) {
            assertTrue(DesktopWindowsControlOnlyStartup.allowsPending(args), args.toString())
            var requested = 0
            val code = DesktopWindowsControlOnlyStartup.execute(args.toTypedArray(), {}, {
                requested++; DesktopCliResponse.failure("UNAVAILABLE", 2)
            })
            assertEquals(2, code)
            assertEquals(1, requested)
        }
        for (args in listOf(emptyList(), listOf("serve"), listOf("on"), listOf("updates", "install"),
            listOf("updates", "check"), listOf("settings", "set", "theme", "dark"), listOf("--android", "status"),
            listOf("status", "--watch"), listOf("operations", "wait", "opaque"), listOf("status", "--typo"),
            listOf("--async", "status"), listOf("--if-revision", "0", "status")))
            assertFalse(DesktopWindowsControlOnlyStartup.allowsPending(args), args.toString())
        assertTrue(DesktopWindowsControlOnlyStartup.isBlockingWait(listOf("--json", "operations", "wait", "opaque")))
    }
}
