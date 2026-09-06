package com.kardinal.vpncontrol.desktop

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class DesktopMacInstallJobAclTest {
    private class Fake(var lookupError: Int = 0, var firstResult: Int = -1, var firstError: Int = 22,
        var valid: Boolean = true,
    ) : DesktopMacInstallJobAcl.Api {
        var freed = 0
        override fun acl_get_link_np(path: String, type: Int): Pointer? {
            assertEquals(0x100, type); Native.setLastError(lookupError)
            return if (lookupError == 0) Pointer(1) else null
        }
        override fun acl_get_fd_np(fd: Int, type: Int) = acl_get_link_np("", type)
        override fun acl_valid(acl: Pointer) = if (valid) 0 else -1
        override fun acl_get_entry(acl: Pointer, entryId: Int, entry: PointerByReference): Int {
            assertEquals(0, entryId); Native.setLastError(firstError); return firstResult
        }
        override fun acl_free(acl: Pointer): Int { freed++; return 0 }
    }
    @Test fun onlyValidEmptyAclIsAcceptedAndNativeMemoryAlwaysFreed() {
        val empty = Fake()
        DesktopMacInstallJobAcl.requireAbsent(Path.of("unused"), empty)
        assertEquals(1, empty.freed)
        listOf(Fake(firstResult = 0), Fake(valid = false), Fake(firstError = 5)).forEach {
            assertFails { DesktopMacInstallJobAcl.requireAbsent(Path.of("unused"), it) }
            assertEquals(1, it.freed)
        }
    }
    @Test fun absentAclDoesNotExcuseMissingTargetSymlinkOrInspectionFailure() {
        val base = Files.createTempDirectory("installer-acl-test-")
        try {
            DesktopMacInstallJobAcl.requireAbsent(base, Fake(lookupError = 2))
            assertFails { DesktopMacInstallJobAcl.requireAbsent(base.resolve("missing"), Fake(lookupError = 2)) }
            assertFails { DesktopMacInstallJobAcl.requireAbsent(base, Fake(lookupError = 13)) }
            if (!System.getProperty("os.name").startsWith("Windows", true)) {
                val link = base.resolve("link"); Files.createSymbolicLink(link, base)
                assertFails { DesktopMacInstallJobAcl.requireAbsent(link, Fake(lookupError = 2)) }
            }
        } finally { base.toFile().deleteRecursively() }
    }
    @Test fun actualMacDescriptorRejectsExtendedAclOnTestOwnedDirectory() {
        if (!System.getProperty("os.name").startsWith("Mac", true)) return
        val base = Files.createTempDirectory("installer-native-acl-").toRealPath()
        try {
            val backend = DesktopMacInstallJobBackend { _, _ -> }
            backend.openRoot(base, false).close()
            val command = ProcessBuilder("/bin/chmod", "+a", "everyone allow write", base.toString()).start()
            assertTrue(command.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(0, command.exitValue())
            assertFails { backend.openRoot(base, false) }
            assertFails { DesktopMacInstallJobBackend().openRoot(base, false) }
        } finally { base.toFile().deleteRecursively() }
    }
}
