package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode

/** Bounded, single-reader view of one exact completed macOS authorization child. */
internal class DesktopMacAuthorizationCollector(private val jobId: String, private val process: Process) {
    private var completed = false
    private var reply: ControlCode? = null

    @Synchronized fun poll(): ControlCode? {
        if (completed) return reply
        if (process.isAlive) return null
        completed = true
        reply = DesktopMacAuthorizationReply.notStartedCode(jobId, process.exitValue(),
            process.inputStream.use { it.readNBytes(MAX_REPLY_BYTES + 1) })
        return reply
    }

    private companion object { const val MAX_REPLY_BYTES = 256 }
}
