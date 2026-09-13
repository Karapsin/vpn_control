package com.kardinal.vpncontrol.desktop

import com.sun.jna.Pointer
import com.sun.jna.platform.win32.WinNT
import kotlin.test.*

class DesktopWindowsInstallCoordinatorLaunchTest {
    private val job = "00000000-0000-0000-0000-000000000001"

    @Test fun verifiesReturnedProcessBeforeReleasingItsHandle() {
        val events = mutableListOf<String>()
        val handle = WinNT.HANDLE(Pointer(123))
        val helper = helper { actual -> assertSame(handle, actual); events += "verify" }
        launchWindowsInstallCoordinator(helper, job, launch = { executable, arguments ->
            assertEquals(helper.executable, executable)
            assertEquals(helper.parameters(job), arguments)
            events += "launch"; handle
        }, closeProcess = { actual -> assertSame(handle, actual); events += "close" })
        assertEquals(listOf("launch", "verify", "close"), events)
    }

    @Test fun failedImageVerificationReleasesHandleAndPreservesFailureWithoutAnotherLaunch() {
        var launches = 0
        var closes = 0
        val failure = IllegalStateException("PERMISSION_DENIED")
        val actual = assertFailsWith<IllegalStateException> {
            launchWindowsInstallCoordinator(helper { throw failure }, job,
                launch = { _, _ -> launches++; WinNT.HANDLE(Pointer(123)) },
                closeProcess = { closes++ })
        }
        assertSame(failure, actual)
        assertEquals(1, launches)
        assertEquals(1, closes)
    }

    @Test fun deniedLaunchNeverVerifiesOrClosesAnUnreturnedProcess() {
        val failure = IllegalStateException("CANCELLED")
        val actual = assertFailsWith<IllegalStateException> {
            launchWindowsInstallCoordinator(helper { fail("No returned process") }, job,
                launch = { _, _ -> throw failure }, closeProcess = { fail("No returned handle") })
        }
        assertSame(failure, actual)
    }

    private fun helper(verify: (WinNT.HANDLE) -> Unit) = object : DesktopWindowsInstallHelperLease {
        override val executable = "C:\\Program Files\\VPN Control\\app\\native\\windows-amd64\\vpn-control-install-helper.exe"
        override val owner = DesktopWindowsRuntimeResourceNativeOwner(123, 133000000000000001, "S-1-5-21-1-2-3-1001")
        override fun parameters(jobId: String) = DesktopWindowsInstallHelperInvocation(
            DesktopWindowsInstallHelperInvocation.Role.COORDINATOR, jobId, owner.processId, owner.creationFileTime,
        ).arguments().joinToString(" ", transform = ::windowsInstallArgument)
        override fun verifyStartedProcess(process: WinNT.HANDLE) = verify(process)
        override fun close() = Unit
    }
}
