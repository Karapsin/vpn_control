package com.kardinal.vpncontrol.desktop

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Only the exact successful terminal response may release a requested owner exit. */
internal class DesktopOwnerExitGate {
    private val pending = AtomicReference<String?>(null)
    private val released = AtomicBoolean()
    val exitRequested: Boolean get() = released.get()

    fun requestExitAfterResponse(requestId: String) {
        require(requestId.isNotBlank() && requestId.length <= 256)
        check(pending.compareAndSet(null, requestId) || pending.get() == requestId)
    }

    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) {
        val request = (command as? DesktopCliCommand.ControlSubmit)?.request ?: return
        if (!response.success || pending.get() != request.requestId) return
        val result = runCatching {
            com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.message)
        }.getOrNull() ?: return
        if (result.requestId == request.requestId && result.controllerId == request.controllerId &&
            result.final && result.code == com.kardinal.vpncontrol.model.ControlCode.OK && response.exitCode == 0)
            released.set(true)
    }
}
