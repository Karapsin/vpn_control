package com.kardinal.vpncontrol.desktop

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread

internal enum class DesktopActivationShowResult { SHOWN, HEADLESS, UNAVAILABLE }

internal class DesktopActivationServer private constructor(
    private val listener: ServerSocket,
    private val acceptor: Thread,
    private val workers: ThreadPoolExecutor,
    private val clients: MutableSet<Socket>,
    private val portFile: Path,
    private val endpoint: DesktopControlEndpoint,
    private val documents: DesktopControlDocuments,
) : AutoCloseable {
    fun hasRetainedTransfers(): Boolean = documents.hasWork()
    override fun close() {
        runCatching { listener.close() }
        clients.forEach { runCatching { it.close() } }
        workers.shutdown()
        runCatching { documents.close() }
        runCatching { acceptor.join(250) }
        runCatching {
            if (DesktopControlEndpoint.read(portFile).controllerId == endpoint.controllerId) Files.deleteIfExists(portFile)
        }
    }

    companion object {
        private val defaultPortFile: Path get() = DesktopWorkspacePaths.root().resolve("activation.port")

        fun start(
            onShowWindow: () -> DesktopActivationShowResult,
            onCliCommand: (DesktopCliCommand) -> DesktopCliResponse = {
                DesktopCliResponse.failure("VPN Control desktop app is not ready.", 2)
            },
            portFile: Path = defaultPortFile,
            onCliCommandFinished: () -> Unit = {},
            controllerId: String = java.util.UUID.randomUUID().toString(),
            onCliResponseFlushed: (DesktopCliCommand, DesktopCliResponse) -> Unit = { _, _ -> },
        ): DesktopActivationServer? {
            val server = ServerSocket()
            val workers = ThreadPoolExecutor(0, 16, 30, TimeUnit.SECONDS, SynchronousQueue(), { task ->
                Thread(task, "vpn-control-client").apply { isDaemon = true }
            })
            val clients = ConcurrentHashMap.newKeySet<Socket>()
            return try {
                server.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
                val endpoint = DesktopControlEndpoint.create(server.localPort, controllerId)
                val documents = DesktopControlDocuments(controllerId)
                endpoint.publish(portFile)
                val mutation = ReentrantLock()
                val acceptor = thread(name = "vpn-control-activation", isDaemon = true) {
                    while (!server.isClosed) {
                        val client = try { server.accept() } catch (_: Exception) { break }
                        clients.add(client)
                        try {
                            workers.execute {
                                var commandInvoked = false
                                var admittedCommand: DesktopCliCommand? = null
                                var admittedResponse: DesktopCliResponse? = null
                                try {
                                    client.use { socket ->
                                        socket.soTimeout = 3000
                                        val input = DataInputStream(socket.getInputStream())
                                        val output = DataOutputStream(socket.getOutputStream())
                                        val credential = DesktopControlFrames.read(input)
                                        if (!MessageDigest.isEqual(credential.toByteArray(), endpoint.token.toByteArray())) {
                                            DesktopControlFrames.write(output, "PERMISSION_DENIED")
                                            return@use
                                        }
                                        DesktopControlFrames.write(output, "AUTHENTICATED")
                                        val first = DesktopControlFrames.read(input)
                                        val context = documents.readContext(first)
                                        val incoming = if (context != null) DesktopControlFrames.read(input) else first
                                        val transferResponse = documents.handle(incoming)
                                        if (transferResponse != null) {
                                            DesktopControlFrames.write(output, transferResponse)
                                            documents.responseFlushed(incoming)
                                            return@use
                                        }
                                        val command = documents.consume(incoming, context?.first)
                                        val response = if (command == "show") {
                                            when (onShowWindow()) {
                                                DesktopActivationShowResult.SHOWN -> "ok"
                                                DesktopActivationShowResult.HEADLESS -> "headless"
                                                DesktopActivationShowResult.UNAVAILABLE -> "unavailable"
                                            }
                                        } else {
                                            val result = DesktopCliProtocol.decodeCommandDocument(command).fold(
                                                onSuccess = { decoded ->
                                                    require(context == null || context.second == documentKind(decoded))
                                                    if (decoded.bypassesMutationAdmission) {
                                                        commandInvoked = true
                                                        admittedCommand = decoded
                                                        onCliCommand(decoded).also { admittedResponse = it }
                                                    }
                                                    else if (!mutation.tryLock()) DesktopCliResponse.failure("VPN Control is busy.")
                                                    else try {
                                                        commandInvoked = true
                                                        admittedCommand = decoded
                                                        onCliCommand(decoded).also { admittedResponse = it }
                                                    } finally { mutation.unlock() }
                                                },
                                                onFailure = { DesktopCliResponse.failure("Invalid VPN Control CLI command.") },
                                            )
                                            DesktopCliProtocol.encodeResponse(result)
                                        }
                                        val completedCommand = admittedCommand
                                        val completedResponse = admittedResponse
                                        val flushed = {
                                            if (completedCommand != null && completedResponse != null)
                                                onCliResponseFlushed(completedCommand, completedResponse)
                                        }
                                        if (DesktopControlFrames.fits(response)) {
                                            DesktopControlFrames.write(output, response)
                                            flushed()
                                        } else if (context == null) {
                                            DesktopControlFrames.write(output, DesktopCliProtocol.encodeResponse(
                                                DesktopCliResponse.failure("INCOMPATIBLE_PROTOCOL", 2)))
                                        } else {
                                            DesktopControlFrames.write(output, documents.publish(response, documentKind(completedCommand),
                                                context.first, flushed))
                                        }
                                    }
                                } catch (_: Exception) {
                                    // Invalid/disconnected clients cannot kill the accept loop or leak payloads.
                                } finally {
                                    clients.remove(client)
                                    runCatching { client.close() }
                                    // Notify the owner only after response framing and socket cleanup.
                                    // A transient owner may shut down immediately on this notification.
                                    if (commandInvoked) runCatching { onCliCommandFinished() }
                                }
                            }
                        } catch (_: java.util.concurrent.RejectedExecutionException) {
                            clients.remove(client)
                            runCatching { client.close() }
                        }
                    }
                }
                DesktopActivationServer(server, acceptor, workers, clients, portFile, endpoint, documents)
            } catch (_: Exception) {
                runCatching { server.close() }
                workers.shutdown()
                null
            }
        }

        private fun request(payload: String, portFile: Path, responseTimeout: Long, documentKind: String? = null,
            payloadForController: ((String) -> String)? = null): String =
            request(payload, DesktopControlEndpoint.read(portFile), responseTimeout, documentKind, payloadForController)

        private fun request(payload: String, endpoint: DesktopControlEndpoint, responseTimeout: Long, documentKind: String? = null,
            payloadForController: ((String) -> String)? = null): String {
            val bound = payloadForController?.invoke(endpoint.controllerId) ?: payload
            fun exchange(value: String) = exchange(endpoint, value, responseTimeout)
            if (documentKind == null) return exchange(bound)
            if (!endpoint.documentTransfers) {
                if (!DesktopControlFrames.fits(bound)) throw DesktopControlProtocolException()
                return exchange(bound)
            }
            val context = java.util.UUID.randomUUID().toString()
            var discard: (() -> Unit)? = null
            try {
                val outgoing = if (DesktopControlFrames.fits(bound)) bound else {
                    val upload = DesktopControlDocuments.upload(endpoint.controllerId, bound, context, ::exchange)
                    discard = upload.second
                    upload.first
                }
                val response = exchange(endpoint, outgoing, responseTimeout,
                    DesktopControlDocuments.context(endpoint.controllerId, context, documentKind))
                return DesktopControlDocuments.download(endpoint.controllerId, response, documentKind, context, ::exchange)
            } finally { discard?.let { runCatching(it) } }
        }

        private fun exchange(endpoint: DesktopControlEndpoint, payload: String, responseTimeout: Long, context: String? = null): String {
            return Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), endpoint.port), 500)
                socket.soTimeout = 3000
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                DesktopControlFrames.write(output, endpoint.token)
                if (DesktopControlFrames.read(input) != "AUTHENTICATED") return@use "PERMISSION_DENIED"
                if (context != null) DesktopControlFrames.write(output, context)
                DesktopControlFrames.write(output, payload)
                DesktopControlFrames.read(DataInputStream(DesktopControlResponseInputStream(
                    input, responseTimeout, { socket.soTimeout = it })))
            }
        }

        fun requestShow(portFile: Path = defaultPortFile): DesktopActivationShowResult = runCatching {
            when (request("show", portFile, 3000)) {
                "ok" -> DesktopActivationShowResult.SHOWN
                "headless" -> DesktopActivationShowResult.HEADLESS
                else -> DesktopActivationShowResult.UNAVAILABLE
            }
        }.getOrDefault(DesktopActivationShowResult.UNAVAILABLE)

        fun requestCliCommand(command: DesktopCliCommand, portFile: Path = defaultPortFile): DesktopCliResponse =
            requestCliCommandUsing(command, null) { DesktopControlEndpoint.read(portFile) }

        internal fun requestCliCommandAtEndpoint(command: DesktopCliCommand, endpoint: DesktopControlEndpoint,
            responseTimeoutMillis: Long): DesktopCliResponse = requestCliCommandUsing(command, responseTimeoutMillis) { endpoint }

        private fun requestCliCommandUsing(command: DesktopCliCommand, responseTimeoutMillis: Long?,
            endpoint: () -> DesktopControlEndpoint): DesktopCliResponse = try {
            val timeoutMillis = responseTimeoutMillis ?: if (command is DesktopCliCommand.ControlFrontendLease || command is DesktopCliCommand.ControlFrontendIdentityRead) 3_000L
                else if (command is DesktopCliCommand.ControlSnapshotRead || command is DesktopCliCommand.ControlPresentationRead) 10_000L
                else (command as? DesktopCliCommand.ControlSubmit)?.clientTimeoutSeconds?.times(1000) ?: 600_000L
            val response = request("", endpoint(), timeoutMillis, documentKind(command)) { controllerId ->
                val bound = when {
                    command is DesktopCliCommand.ControlSubmit && command.request.controllerId == null ->
                        command.copy(request = command.request.copy(controllerId = controllerId))
                    command is DesktopCliCommand.ControlSnapshotRead && command.controllerId == null ->
                        command.copy(controllerId = controllerId)
                    command is DesktopCliCommand.ControlPresentationRead && command.controllerId == null ->
                        command.copy(controllerId = controllerId)
                    else -> command
                }
                DesktopCliProtocol.encodeCommandDocument(bound)
            }
            if (response == "PERMISSION_DENIED") DesktopCliResponse.failure(response)
            else DesktopCliProtocol.decodeResponse(response)
        } catch (_: NoSuchFileException) {
            DesktopCliResponse.notRunning()
        } catch (_: ConnectException) {
            DesktopCliResponse.notRunning()
        } catch (_: SocketTimeoutException) {
            DesktopCliResponse.failure("TIMEOUT", 2)
        } catch (_: DesktopControlProtocolException) {
            DesktopCliResponse.failure("INCOMPATIBLE_PROTOCOL", 2)
        } catch (_: Exception) {
            DesktopCliResponse.failure("OUTCOME_UNKNOWN", 2)
        }

        private fun documentKind(command: DesktopCliCommand?): String = when (command) {
            is DesktopCliCommand.ControlSnapshotRead -> "snapshot"
            is DesktopCliCommand.ControlPresentationRead -> "presentation"
            else -> "response"
        }
    }
}
