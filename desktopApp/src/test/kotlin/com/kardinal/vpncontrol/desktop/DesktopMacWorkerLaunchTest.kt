package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopMacWorkerLaunchTest {
    private val job = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
    private val worker = Path.of("/Users/東京/' dollar$ (not a command)/vpn-control-install-worker")
    @Test fun localHasNoElevationAndMachineUsesConstantScriptWithOnlyQuotedArgv() {
        val local = DesktopMacWorkerLaunch.coordinator(worker, DesktopMacInstallAuthority.USER_LOCAL, job, 123)
        assertEquals(listOf(worker.toString(), "--coordinate", job, "123"), local)
        val machine = DesktopMacWorkerLaunch.coordinator(worker, DesktopMacInstallAuthority.MACHINE, job, 123)
        assertEquals(listOf("/usr/bin/osascript", "-e"), machine.take(2))
        assertEquals("--", machine[3])
        assertEquals(local, machine.drop(4))
        assertFalse(machine[2].contains(worker.toString()))
        assertEquals(4, Regex("quoted form of").findAll(machine[2]).count())
        assertTrue(machine[2].contains("with administrator privileges"))
        assertEquals("--watch", DesktopMacWorkerLaunch.watcher(worker, job, 123)[1])
    }
    @Test fun launchRequiresExactWorkerLeafCanonicalJobAndBoundedNativePid() {
        assertFails { DesktopMacWorkerLaunch.watcher(worker.resolveSibling("other"), job, 123) }
        assertFails { DesktopMacWorkerLaunch.watcher(worker, "not-a-job", 123) }
        assertFails { DesktopMacWorkerLaunch.watcher(worker, job, 0) }
        assertFails { DesktopMacWorkerLaunch.watcher(Path.of("/tmp/../vpn-control-install-worker"), job, 123) }
    }
}
