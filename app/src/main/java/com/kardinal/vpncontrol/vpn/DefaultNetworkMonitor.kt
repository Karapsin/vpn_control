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
        defaultNetwork = manager.activeNetwork
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                update(network)
            }

            override fun onLost(network: Network) {
                if (defaultNetwork == network) {
                    update(connectivityManager?.activeNetwork)
                }
            }

            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: android.net.NetworkCapabilities,
            ) {
                if (defaultNetwork == network) {
                    notifyListener(network)
                }
            }

            override fun onLinkPropertiesChanged(
                network: Network,
                linkProperties: android.net.LinkProperties,
            ) {
                if (defaultNetwork == network) {
                    notifyListener(network)
                }
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
        return defaultNetwork ?: connectivityManager?.activeNetwork ?: error("android: no default network")
    }

    fun setListener(listener: InterfaceUpdateListener?) {
        this.listener = listener
        notifyListener(defaultNetwork ?: connectivityManager?.activeNetwork)
    }

    private fun update(network: Network?) {
        defaultNetwork = network
        notifyListener(network)
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

    private const val TAG = "DefaultNetworkMonitor"
}
