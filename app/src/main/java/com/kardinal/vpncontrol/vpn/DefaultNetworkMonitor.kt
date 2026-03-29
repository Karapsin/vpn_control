package com.kardinal.vpncontrol.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import com.kardinal.vpncontrol.data.DiagnosticsLogger
import io.nekohasekai.libbox.InterfaceUpdateListener
import java.net.NetworkInterface

object DefaultNetworkMonitor {
    @Volatile
    private var connectivityManager: ConnectivityManager? = null

    @Volatile
    private var defaultNetwork: Network? = null

    @Volatile
    private var listener: InterfaceUpdateListener? = null

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Synchronized
    fun start(context: Context) {
        if (connectivityManager != null) return
        val manager = context.getSystemService(ConnectivityManager::class.java)
        connectivityManager = manager
        defaultNetwork = preferredNetwork(manager)
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                updatePreferred()
            }

            override fun onLost(network: Network) {
                updatePreferred()
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: android.net.NetworkCapabilities,
            ) {
                updatePreferred()
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: android.net.LinkProperties,
            ) {
                updatePreferred()
            }
        }
        runCatching {
            manager.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        }.onFailure { error ->
            Log.e(TAG, "Failed to register default network callback", error)
            DiagnosticsLogger.append(context, "DefaultNetworkMonitor registration failed", error)
        }
        notifyListener(defaultNetwork)
    }

    @Synchronized
    fun stop() {
        val manager = connectivityManager
        val callback = networkCallback
        if (manager != null && callback != null) {
            runCatching { manager.unregisterNetworkCallback(callback) }
        }
        connectivityManager = null
        networkCallback = null
        defaultNetwork = null
        listener = null
    }

    fun requireNetwork(): Network {
        return defaultNetwork
            ?: connectivityManager?.let(::preferredNetwork)
            ?: error("android: no default network")
    }

    fun setListener(listener: InterfaceUpdateListener?) {
        this.listener = listener
        notifyListener(defaultNetwork ?: connectivityManager?.let(::preferredNetwork))
    }

    private fun update(network: Network?) {
        defaultNetwork = network
        notifyListener(network)
    }

    private fun updatePreferred() {
        val manager = connectivityManager ?: return
        update(preferredNetwork(manager))
    }

    private fun notifyListener(network: Network?) {
        val listener = listener ?: return
        val manager = connectivityManager ?: return
        if (network == null) {
            listener.updateDefaultInterface("", -1, false, false)
            return
        }
        val linkProperties = manager.getLinkProperties(network) ?: return
        val networkCapabilities = manager.getNetworkCapabilities(network)
        val interfaceName = linkProperties.interfaceName ?: return
        val interfaceIndex = runCatching {
            NetworkInterface.getByName(interfaceName)?.index ?: -1
        }.getOrDefault(-1)
        val isExpensive = networkCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)?.not() ?: false
        val isConstrained =
            networkCapabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)?.not() ?: false
        listener.updateDefaultInterface(interfaceName, interfaceIndex, isExpensive, isConstrained)
    }

    private fun preferredNetwork(manager: ConnectivityManager): Network? {
        val active = manager.activeNetwork
        if (active != null && isUsableUnderlyingNetwork(manager, active)) {
            return active
        }
        return manager.allNetworks.firstOrNull { network ->
            isUsableUnderlyingNetwork(manager, network)
        } ?: active
    }

    private fun isUsableUnderlyingNetwork(manager: ConnectivityManager, network: Network): Boolean {
        val capabilities = manager.getNetworkCapabilities(network) ?: return false
        if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
            return false
        }
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return false
        }
        val interfaceName = manager.getLinkProperties(network)?.interfaceName ?: return false
        if (interfaceName == "vpn-control" || interfaceName.startsWith("tun")) {
            return false
        }
        return true
    }

    private const val TAG = "DefaultNetworkMonitor"
}
