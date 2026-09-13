package com.kardinal.vpncontrol.desktop

import com.sun.jna.platform.win32.WinNT

/** Admission for the fixed NativeAOT installer coordinator. */
internal object DesktopWindowsInstallHelperAdmission {
    private const val HELPER = "vpn-control-install-helper.exe"
    private val OPERATIONS = listOf("validate-only", "install-user", "install-coordinator")

    fun retain(native: WindowsVpnHelperNative = JnaWindowsVpnHelperNative()): DesktopWindowsInstallHelperLease {
        val admitted = DesktopWindowsPackagedHelperAdmission.retain(HELPER, OPERATIONS, native = native)
        return object : DesktopWindowsInstallHelperLease {
            override val executable get() = admitted.executable
            override val owner get() = admitted.owner
            override fun parameters(jobId: String): String {
                admitted.assertOpen()
                val arguments = DesktopWindowsInstallHelperInvocation(
                    DesktopWindowsInstallHelperInvocation.Role.COORDINATOR, jobId, owner.processId, owner.creationFileTime,
                ).arguments().joinToString(" ", transform = ::windowsInstallArgument)
                if (windowsInstallArgument(executable).length.toLong() + arguments.length + 2 > 32767)
                    throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED")
                return arguments
            }
            override fun verifyStartedProcess(process: WinNT.HANDLE) = admitted.verifyStartedProcess(process)
            override fun close() = admitted.close()
            override fun toString() = "Packaged Windows installer helper (<redacted>)"
        }
    }
}

internal interface DesktopWindowsInstallHelperLease : AutoCloseable {
    val executable: String
    val owner: DesktopWindowsRuntimeResourceNativeOwner
    fun parameters(jobId: String): String
    fun verifyStartedProcess(process: WinNT.HANDLE)
}
