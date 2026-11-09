package com.kardinal.vpncontrol.desktop

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * Local ports for the runtimes this app starts: every free-port probe and availability check binds
 * the IPv4 loopback that the generated sing-box inbounds listen on and readiness probes connect to.
 *
 * A wildcard bind such as `ServerSocket(0)` listens on every interface, even for a moment, and
 * Windows Defender Firewall then asks the user to allow network access for the app although only
 * loopback clients ever connect. The control endpoint ([DesktopActivationServer]) binds
 * [InetAddress.getLoopbackAddress], which its clients connect to.
 */
internal object DesktopLoopback {
    /** The IPv4 loopback, never a name lookup. */
    val address: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    /** A socket listening on the loopback [port]; 0 takes a free port from the OS. */
    fun serverSocket(port: Int = 0): ServerSocket = ServerSocket(port, DEFAULT_BACKLOG, address)

    /** A port that was free on the loopback when probed, other than [excluding]. */
    fun freePort(excluding: Int? = null): Int {
        while (true) {
            val candidate = serverSocket().use { it.localPort }
            if (candidate != excluding) return candidate
        }
    }

    /** Whether [port] can be bound on the loopback now, without address reuse. */
    fun isPortAvailable(port: Int): Boolean = runCatching {
        ServerSocket().use { socket ->
            socket.reuseAddress = false
            socket.bind(InetSocketAddress(address, port))
        }
        true
    }.getOrDefault(false)

    /** The backlog of `ServerSocket(port)`. */
    private const val DEFAULT_BACKLOG = 50
}
