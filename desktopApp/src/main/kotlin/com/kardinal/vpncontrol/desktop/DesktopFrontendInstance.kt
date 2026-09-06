package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/** Single presentation process per workspace, independent of the controller lock/lifetime. */
internal class DesktopFrontendInstance private constructor(
    val identity: String,
    private val lock: DesktopSingleInstanceLock,
    private val server: DesktopActivationServer,
) : AutoCloseable {
    private val closed = AtomicBoolean()

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            try { server.close() } finally { lock.close() }
        }
    }

    companion object {
        fun start(directory: Path, visibility: DesktopFrontendVisibility): DesktopFrontendInstance? {
            val lock = DesktopSingleInstanceLock.acquire(directory.resolve("frontend.lock")) ?: return null
            val identity = UUID.randomUUID().toString()
            val server = DesktopActivationServer.start(
                onShowWindow = {
                    if (visibility.request(true) == ControlCode.OK) DesktopActivationShowResult.SHOWN
                    else DesktopActivationShowResult.UNAVAILABLE
                },
                onCliCommand = { command ->
                    if (command is DesktopCliCommand.ControlFrontendIdentityRead) {
                        DesktopFrontendProcessIdentity.response(command, identity)
                    } else {
                    // Window control and self-identity only; no runtime/configuration forwarding.
                    val request = (command as? DesktopCliCommand.ControlSubmit)?.request
                    when {
                        request == null -> DesktopCliResponse.failure("UNSUPPORTED")
                        request.controllerId != identity -> DesktopCliResponse.failure("CONFLICT")
                        request.command.operation in setOf(ControlOperationId.GUI_SHOW, ControlOperationId.GUI_HIDE) -> {
                            val owner = (request.command.arguments["owner"] as? ControlValue.Text)?.value
                            val code = if (request.command.arguments.keys != setOf("owner") || request.ifRevision != null ||
                                request.asynchronous || request.interactive) ControlCode.INVALID_ARGUMENT
                            else visibility.request(request.command.operation == ControlOperationId.GUI_SHOW, owner)
                            DesktopCliResponse(code == ControlCode.OK,
                                com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeResult(ControlResult(identity,
                                    request.requestId, code, 0, final = code !in uncertainVisibilityCodes)), code.exitCode)
                        }
                        else -> DesktopCliResponse.failure("UNSUPPORTED")
                    }
                    }
                },
                portFile = endpoint(directory),
                controllerId = identity,
            )
            if (server == null) {
                lock.close()
                return null
            }
            return DesktopFrontendInstance(identity, lock, server)
        }

        fun show(directory: Path): DesktopActivationShowResult = DesktopActivationServer.requestShow(endpoint(directory))

        fun hide(directory: Path, ownerId: String): DesktopCliResponse = DesktopActivationServer.requestCliCommand(
            DesktopCliCommand.ControlSubmit(ControlRequest(UUID.randomUUID().toString(),
                ControlCommand(ControlOperationId.GUI_HIDE, mapOf("owner" to ControlValue.Text(ownerId)))), clientTimeoutSeconds = 3), endpoint(directory))

        internal fun endpoint(directory: Path): Path = directory.resolve("frontend.port")
    }
}
