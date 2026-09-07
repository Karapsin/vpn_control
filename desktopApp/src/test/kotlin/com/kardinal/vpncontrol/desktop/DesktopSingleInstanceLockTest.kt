package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DesktopSingleInstanceLockTest {
    @Test
    fun createsMissingWorkspaceDirectoriesPrivateBeforeOpeningLock() {
        val parent = Files.createTempDirectory("vpn-control-private-workspace")
        try {
            if (!Files.getFileStore(parent).supportsFileAttributeView("posix")) return
            val workspace = parent.resolve("new-parent/workspace")
            assertNotNull(DesktopSingleInstanceLock.acquire(workspace.resolve("vpn-control.lock"))).use {
                val privateMode = PosixFilePermissions.fromString("rwx------")
                assertEquals(privateMode, Files.getPosixFilePermissions(workspace.parent))
                assertEquals(privateMode, Files.getPosixFilePermissions(workspace))
            }
        } finally { parent.toFile().deleteRecursively() }
    }

    @Test
    fun secondLockFailsUntilFirstLockIsClosed() {
        val tempDir = Files.createTempDirectory("vpn-control-single-instance")
        val lockFile = tempDir.resolve("vpn-control.lock")
        try {
            val first = DesktopSingleInstanceLock.acquire(lockFile)
            assertNotNull(first)
            first.use {
                assertNull(DesktopSingleInstanceLock.acquire(lockFile))
            }
            DesktopSingleInstanceLock.acquire(lockFile)?.use { reacquired ->
                assertNotNull(reacquired)
            }
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }
}
