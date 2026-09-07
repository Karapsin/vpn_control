package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopLinuxInstallRequestTest {
    private fun request() = DesktopLinuxInstallRequest("00000000-0000-0000-0000-000000000001", 123, 456,
        1000, "deb", "a".repeat(64), 12, "/home/user/東京 update.deb", "/opt/vpn-control/bin/vpn-control", "/home/user/state")

    @Test fun fixedFieldsPreserveUnicodeAndShellMetacharactersAsData() {
        val value = request().copy(packageFile = "/home/user/\$(touch marker); '東京'.deb")
        val fields = value.encode().decodeToString().split('\n')
        assertEquals(14, fields.size)
        assertEquals(value.packageFile, fields[8])
        assertEquals("", fields.last())
        assertFalse(value.toString().contains(value.packageFile))
    }

    @Test fun recordsRejectLineInjectionUnsupportedPackagesAndUnidentifiedProcesses() {
        assertFails { request().copy(packageFile = "/home/user/a\nmalicious") }
        assertFails { request().copy(launcher = "/bin/sh") }
        assertEquals("arch-bundle", request().copy(packageType = "arch-bundle").encode().decodeToString().split('\n')[5])
        assertFails { request().copy(packageType = "zip") }
        assertFails { request().copy(ownerUid = 0) }
        assertFails { request().copy(frontendPid = 4, frontendStartTicks = 0) }
    }

    @Test fun capturedWorkerArgumentsContainOnlyOpaqueIdentityAndFixedSource() {
        val value = request()
        val arguments = DesktopLinuxCapturedInstallWorker.arguments(value.jobId, value.ownerPid)
        assertEquals(listOf("/bin/sh", "-c"), arguments.take(2))
        assertEquals("vpn-control-install-admission", arguments[3])
        assertTrue(arguments[4].contains("read_request()"))
        assertEquals(listOf(value.jobId, "123"), arguments.takeLast(2))
        assertFalse(arguments.contains(value.packageFile))
        assertContains(arguments[4], "publish_receipt AUTHORIZED")
        assertContains(arguments[4], "publish_receipt WAITING_FOR_EXIT")
        assertFails { DesktopLinuxCapturedInstallWorker.arguments(";id", 123) }
    }
}
