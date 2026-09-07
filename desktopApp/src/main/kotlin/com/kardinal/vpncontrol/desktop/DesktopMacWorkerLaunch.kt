package com.kardinal.vpncontrol.desktop

import java.nio.file.Path

/** Only the captured native worker is executable input; paths remain argv data across AppleScript. */
internal object DesktopMacWorkerLaunch {
    fun watcher(worker: Path, jobId: String, ownerPid: Long): List<String> =
        workerArguments(worker, "--watch", jobId, ownerPid)
    fun cleanup(worker: Path, jobId: String, ownerPid: Long): List<String> =
        workerArguments(worker, "--cleanup", jobId, ownerPid)

    fun coordinator(worker: Path, authority: DesktopMacInstallAuthority, jobId: String, ownerPid: Long): List<String> {
        val command = workerArguments(worker, "--coordinate", jobId, ownerPid)
        return if (authority == DesktopMacInstallAuthority.USER_LOCAL) command
        else listOf("/usr/bin/osascript", "-e", AUTHORIZED_SCRIPT, "--") + command
    }

    private fun workerArguments(worker: Path, mode: String, jobId: String, ownerPid: Long): List<String> {
        require(worker.isAbsolute && worker.normalize() == worker && worker.fileName.toString() == "vpn-control-install-worker")
        require(worker.toString().length <= 4096 && worker.toString().none { it.code < 32 || it.code == 127 })
        require(DesktopInstallJobNames.validJob(jobId) && ownerPid in 1..Int.MAX_VALUE)
        return listOf(worker.toString(), mode, jobId, ownerPid.toString())
    }

    // Apple TN2065: quoted form of handles shell metacharacters, and administrator privileges
    // is the OS consent boundary. No user/password, sudo policy, interpreter payload or relaunch.
    private val AUTHORIZED_SCRIPT = """
        on run argv
            if (count of argv) is not 4 then error number 64
            set workerCommand to quoted form of (item 1 of argv) & " " & quoted form of (item 2 of argv) & " " & quoted form of (item 3 of argv) & " " & quoted form of (item 4 of argv)
            try
                do shell script workerCommand with administrator privileges without altering line endings
            on error errorMessage number errorNumber
                if errorNumber is -128 or errorNumber is -60006 or errorNumber is -60005 or errorNumber is -60007 then
                    return "VPN_CONTROL_AUTH_V1" & linefeed & (item 3 of argv) & linefeed & (errorNumber as text)
                end if
                error number errorNumber
            end try
            return ""
        end run
    """.trimIndent()
}
