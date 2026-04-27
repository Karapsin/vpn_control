package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DesktopSingleInstanceLockTest {
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
