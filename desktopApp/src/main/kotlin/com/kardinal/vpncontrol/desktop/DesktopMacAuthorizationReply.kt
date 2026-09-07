package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode

/** A reply is meaningful only from the exact completed osascript child and job. */
internal object DesktopMacAuthorizationReply {
    fun notStartedCode(jobId: String, exitCode: Int, bytes: ByteArray): ControlCode? {
        if (exitCode != 0 || bytes.size > 256 || !DesktopInstallJobNames.validJob(jobId)) return null
        // Exact byte matching rejects foreign jobs, invalid encoding, partial and excess output.
        return listOf(-128 to ControlCode.CANCELLED, -60006 to ControlCode.CANCELLED,
            -60005 to ControlCode.PERMISSION_DENIED, -60007 to ControlCode.INTERACTION_REQUIRED)
            .singleOrNull { (error, _) -> bytes.contentEquals(
                "VPN_CONTROL_AUTH_V1\n$jobId\n$error\n".encodeToByteArray()) }?.second
    }
}
