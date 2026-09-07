package com.kardinal.vpncontrol.desktop

import kotlin.test.*
import org.junit.Assume.assumeTrue

class DesktopMacInstallRequestTest {
    @BeforeTest fun requiresCanonicalPosixWirePaths() {
        // The macOS wire record requires literal POSIX paths and validates them with the default provider.
        assumeTrue("macOS wire paths require a POSIX default file-system provider", java.io.File.separatorChar == '/')
    }

    @Test fun boundedDataOnlyRecordPreservesNativeGenerationAndExplicitAuthority() {
        val request = request()
        val fields = request.encode().decodeToString().split('\n')
        assertEquals(16, fields.size)
        assertEquals("USER_LOCAL", fields[2])
        assertEquals("654321", fields[6])
        assertEquals("/Users/test/東京 app.app", request.bundle.toString())
        assertFalse(request.toString().contains("private-state"))
        assertEquals("MACHINE", request.copy(authority = DesktopMacInstallAuthority.MACHINE).encode().decodeToString().split('\n')[2])
    }
    @Test fun rejectsUnsafePathsAndForeignFrontendWithoutShellEscapingFallback() {
        val request = request()
        for (path in listOf("/tmp/a\nb", "/tmp/../escape", "relative", "/tmp//double", "/tmp/a\u0000"))
            assertFails { request.copy(packageFile = path) }
        assertFails { request.copy(frontend = request.owner.copy(pid = 124, uid = 502)) }
        assertFails { request.copy(frontend = request.owner.copy(pid = 124, executable = "/other/app")) }
        assertFails { request.copy(packageSha256 = "A".repeat(64)) }
        assertFails { request.copy(packageSize = 0) }
    }
    private fun request() = DesktopMacInstallRequest("05dc777a-9bb2-4a73-8d20-b42f45f64a32", DesktopMacInstallAuthority.USER_LOCAL,
        DesktopMacInstallProcess(123, 501, 1700000000, 654321, "/Users/test/東京 app.app/Contents/MacOS/vpn-control"),
        null, "/tmp/package.dmg", 100, "a".repeat(64), "/Users/test/private-state")
}
