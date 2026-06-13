package com.kardinal.vpncontrol.desktop

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.concurrent.thread

internal enum class DesktopActivationShowResult {
    SHOWN,
    HEADLESS,
    UNAVAILABLE,
}

internal class DesktopActivationServer private constructor(
    private val serverSocket: ServerSocket,
    private val serverThread: Thread,
    private val portFile: Path,
) : AutoCloseable {
    override fun close() {
        runCatching { Files.deleteIfExists(portFile) }
        runCatching { serverSocket.close() }
        runCatching { serverThread.join(250) }
    }

    companion object {
        private val defaultStateDir: Path = Path.of(
            System.getProperty("user.home"),
            ".vpn-control-desktop",
        )
        private val defaultPortFile: Path = defaultStateDir.resolve("activation.port")

        fun start(
            onShowWindow: () -> DesktopActivationShowResult,
            onCliCommand: (DesktopCliCommand) -> DesktopCliResponse = {
                DesktopCliResponse.failure(
                    "VPN Control desktop app is not ready.",
                    exitCode = DesktopCliResponse.UNAVAILABLE_EXIT_CODE,
                )
            },
            portFile: Path = defaultPortFile,
        ): DesktopActivationServer? = runCatching {
            Files.createDirectories(portFile.parent)
            val serverSocket = ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
            }
            Files.writeString(portFile, serverSocket.localPort.toString())
            val serverThread = thread(
                name = "vpn-control-activation",
                isDaemon = true,
            ) {
                while (!serverSocket.isClosed) {
                    val client = try {
                        serverSocket.accept()
                    } catch (_: Exception) {
                        break
                    }
                    client.use { socket ->
                        val command = socket.getInputStream()
                            .bufferedReader(StandardCharsets.UTF_8)
                            .readLine()
                        if (command == "show") {
                            val response = when (onShowWindow()) {
                                DesktopActivationShowResult.SHOWN -> "ok"
                                DesktopActivationShowResult.HEADLESS -> "headless"
                                DesktopActivationShowResult.UNAVAILABLE -> "unavailable"
                            }
                            socket.getOutputStream().write("$response\n".toByteArray(StandardCharsets.UTF_8))
                        } else if (command != null) {
                            val response = DesktopCliProtocol.decodeCommand(command)
                                .fold(
                                    onSuccess = { decodedCommand ->
                                        runCatching { onCliCommand(decodedCommand) }
                                            .getOrElse { error ->
                                                DesktopCliResponse.failure(
                                                    error.message ?: "VPN Control CLI command failed.",
                                                )
                                            }
                                    },
                                    onFailure = { error ->
                                        DesktopCliResponse.failure(
                                            error.message ?: "Invalid VPN Control CLI command.",
                                            exitCode = 1,
                                        )
                                    },
                                )
                            socket.getOutputStream().write(
                                "${DesktopCliProtocol.encodeResponse(response)}\n"
                                    .toByteArray(StandardCharsets.UTF_8),
                            )
                        }
                    }
                }
            }
            DesktopActivationServer(serverSocket, serverThread, portFile)
        }.getOrNull()

        fun requestShow(portFile: Path = defaultPortFile): DesktopActivationShowResult = runCatching {
            val port = Files.readString(portFile).trim().toInt()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 500)
                socket.soTimeout = 500
                socket.getOutputStream().write("show\n".toByteArray(StandardCharsets.UTF_8))
                socket.getOutputStream().flush()
                when (
                    socket.getInputStream()
                        .bufferedReader(StandardCharsets.UTF_8)
                        .readLine()
                ) {
                    "ok" -> DesktopActivationShowResult.SHOWN
                    "headless" -> DesktopActivationShowResult.HEADLESS
                    else -> DesktopActivationShowResult.UNAVAILABLE
                }
            }
        }.getOrDefault(DesktopActivationShowResult.UNAVAILABLE)

        fun requestCliCommand(
            command: DesktopCliCommand,
            portFile: Path = defaultPortFile,
        ): DesktopCliResponse = runCatching {
            val port = Files.readString(portFile).trim().toInt()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 500)
                socket.getOutputStream().write(
                    "${DesktopCliProtocol.encodeCommand(command)}\n".toByteArray(StandardCharsets.UTF_8),
                )
                socket.getOutputStream().flush()
                val responseLine = socket.getInputStream()
                    .bufferedReader(StandardCharsets.UTF_8)
                    .readLine()
                if (responseLine == null) {
                    DesktopCliResponse.failure("No response from VPN Control desktop app.", exitCode = 2)
                } else {
                    DesktopCliProtocol.decodeResponse(responseLine)
                }
            }
        }.getOrElse {
            DesktopCliResponse.notRunning()
        }
    }
}
