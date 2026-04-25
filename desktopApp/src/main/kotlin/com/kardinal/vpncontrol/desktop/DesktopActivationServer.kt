package com.kardinal.vpncontrol.desktop

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.concurrent.thread

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
        private val stateDir: Path = Path.of(
            System.getProperty("user.home"),
            ".vpn-control-desktop",
        )
        private val portFile: Path = stateDir.resolve("activation.port")

        fun start(onShowWindow: () -> Unit): DesktopActivationServer? = runCatching {
            Files.createDirectories(stateDir)
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
                            onShowWindow()
                            socket.getOutputStream().write("ok\n".toByteArray(StandardCharsets.UTF_8))
                        }
                    }
                }
            }
            DesktopActivationServer(serverSocket, serverThread, portFile)
        }.getOrNull()

        fun requestShow(): Boolean = runCatching {
            val port = Files.readString(portFile).trim().toInt()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 500)
                socket.soTimeout = 500
                socket.getOutputStream().write("show\n".toByteArray(StandardCharsets.UTF_8))
                socket.getOutputStream().flush()
            }
            true
        }.getOrDefault(false)
    }
}
