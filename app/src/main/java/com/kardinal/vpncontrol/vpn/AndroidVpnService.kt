package com.kardinal.vpncontrol.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager.NameNotFoundException
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Base64
import android.util.Log
import androidx.core.app.NotificationCompat
import com.kardinal.vpncontrol.data.DiagnosticsLogger
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.RuntimeFiles
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.Notification as BoxNotification
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.InterfaceAddress
import java.net.NetworkInterface
import java.security.KeyStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class AndroidVpnService : VpnService(), PlatformInterface {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val storage by lazy { ProfileStorage(applicationContext) }
    private val connectivity by lazy { getSystemService(ConnectivityManager::class.java) }
    private val notifications by lazy { getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager }

    private var tunInterface: ParcelFileDescriptor? = null
    private var boxService: BoxService? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> serviceScope.launch { stopVpn("VPN stopped") }
            else -> serviceScope.launch { startVpn() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        runBlocking { stopVpn(null) }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        runBlocking { stopVpn("VPN permission revoked") }
        super.onRevoke()
    }

    private suspend fun startVpn() {
        try {
            DiagnosticsLogger.append(applicationContext, "AndroidVpnService.startVpn invoked")
            createNotificationChannel()
            showForegroundNotification("VPN starting")
            DefaultNetworkMonitor.start(this)

            val configFile = RuntimeFiles.runtimeConfigFile(this)
            val configContent = configFile.takeIf { it.exists() }?.readText()?.takeIf { it.isNotBlank() }
                ?: error("VPN config missing")

            runCatching { boxService?.close() }
            boxService = Libbox.newService(configContent, this)
            boxService?.start()

            storage.updateVpnRunning(true)
            storage.updateStatus("VPN started")
            showForegroundNotification("VPN running")
        } catch (error: Throwable) {
            Log.e(TAG, "Failed to start VPN", error)
            DiagnosticsLogger.append(applicationContext, "Failed to start VPN", error)
            stopVpn(error.message ?: "Failed to start VPN")
        }
    }

    private suspend fun stopVpn(statusMessage: String?) {
        DiagnosticsLogger.append(applicationContext, "AndroidVpnService.stopVpn invoked: ${statusMessage ?: "no status"}")
        runCatching { boxService?.close() }
        boxService = null

        runCatching { tunInterface?.close() }
        tunInterface = null

        DefaultNetworkMonitor.stop()
        storage.updateVpnRunning(false)
        if (!statusMessage.isNullOrBlank()) {
            storage.updateStatus(statusMessage)
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun localDNSTransport(): LocalDNSTransport = LocalResolver

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun autoDetectInterfaceControl(fd: Int) {
        protect(fd)
    }

    override fun openTun(options: TunOptions): Int {
        if (prepare(this) != null) {
            error("android: missing vpn permission")
        }

        val builder = Builder()
            .setSession("VPN Control")
            .setMtu(options.mtu)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val inet4Address = options.inet4Address
        while (inet4Address.hasNext()) {
            val address = inet4Address.next()
            builder.addAddress(address.address(), address.prefix())
        }

        val inet6Address = options.inet6Address
        while (inet6Address.hasNext()) {
            val address = inet6Address.next()
            builder.addAddress(address.address(), address.prefix())
        }

        if (options.autoRoute) {
            builder.addDnsServer(options.dnsServerAddress.value)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                addRoutes(builder, options)
            } else {
                addLegacyRoutes(builder, options)
            }

            val includePackage = options.includePackage
            while (includePackage.hasNext()) {
                try {
                    builder.addAllowedApplication(includePackage.next())
                } catch (error: NameNotFoundException) {
                    Log.w(TAG, "Skipping unknown allowed package", error)
                }
            }

            val excludePackage = options.excludePackage
            while (excludePackage.hasNext()) {
                try {
                    builder.addDisallowedApplication(excludePackage.next())
                } catch (error: NameNotFoundException) {
                    Log.w(TAG, "Skipping unknown disallowed package", error)
                }
            }
        }

        if (options.isHTTPProxyEnabled && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setHttpProxy(
                ProxyInfo.buildDirectProxy(
                    options.httpProxyServer,
                    options.httpProxyServerPort,
                    options.httpProxyBypassDomain.toList(),
                ),
            )
        }

        val pfd = builder.establish() ?: error("android: VPN is not prepared or has been revoked")
        tunInterface = pfd
        return pfd.fd
    }

    override fun writeLog(message: String) {
        Log.d(TAG, message)
        DiagnosticsLogger.append(applicationContext, "libbox: $message")
    }

    override fun useProcFS(): Boolean = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            error("android: connection owner lookup requires Android 10+")
        }
        val uid = connectivity.getConnectionOwnerUid(
            ipProtocol,
            InetSocketAddress(sourceAddress, sourcePort),
            InetSocketAddress(destinationAddress, destinationPort),
        )
        if (uid == android.os.Process.INVALID_UID) {
            error("android: connection owner not found")
        }
        return uid
    }

    override fun packageNameByUid(uid: Int): String {
        return packageManager.getPackagesForUid(uid)?.firstOrNull().orEmpty()
    }

    override fun uidByPackageName(packageName: String): Int {
        return packageManager.getApplicationInfo(packageName, 0).uid
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        DefaultNetworkMonitor.setListener(listener)
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
        DefaultNetworkMonitor.setListener(null)
    }

    override fun getInterfaces(): NetworkInterfaceIterator {
        val interfaces = mutableListOf<BoxNetworkInterface>()
        val linkInterfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        for (network in connectivity.allNetworks) {
            val linkProperties = connectivity.getLinkProperties(network) ?: continue
            val capabilities = connectivity.getNetworkCapabilities(network) ?: continue
            val interfaceName = linkProperties.interfaceName ?: continue
            val networkInterface = linkInterfaces.find { it.name == interfaceName } ?: continue

            val boxInterface = BoxNetworkInterface().apply {
                name = interfaceName
                index = networkInterface.index
                mtu = runCatching { networkInterface.mtu }.getOrDefault(0)
                addresses = StringListIterator(networkInterface.interfaceAddresses.map { it.toPrefixString() })
                dnsServer = StringListIterator(linkProperties.dnsServers.mapNotNull { it.hostAddress?.substringBefore('%') })
                type = when {
                    capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI.toInt()
                    capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular.toInt()
                    capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet.toInt()
                    else -> Libbox.InterfaceTypeOther.toInt()
                }
                flags = dumpFlags(networkInterface, capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET))
                metered = !capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
            interfaces.add(boxInterface)
        }
        return NetworkInterfaceListIterator(interfaces)
    }

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun systemCertificates(): StringIterator {
        val certificates = mutableListOf<String>()
        val keyStore = KeyStore.getInstance("AndroidCAStore")
        keyStore.load(null, null)
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val cert = keyStore.getCertificate(aliases.nextElement()) ?: continue
            val body = Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
            certificates.add("-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----")
        }
        return StringListIterator(certificates)
    }

    override fun clearDNSCache() {
    }

    override fun sendNotification(notification: BoxNotification) {
        val channelId = notification.identifier.ifBlank { CHANNEL_ID }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            notifications.createNotificationChannel(
                NotificationChannel(
                    channelId,
                    notification.typeName.ifBlank { "VPN Control" },
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
        }
        val builtNotification = NotificationCompat.Builder(this, channelId)
            .setContentTitle(notification.title.ifBlank { "VPN Control" })
            .setContentText(notification.body)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setAutoCancel(true)
            .build()
        notifications.notify(notification.typeID, builtNotification)
    }

    private fun addRoutes(builder: Builder, options: TunOptions) {
        val inet4RouteAddress = options.inet4RouteAddress
        if (inet4RouteAddress.hasNext()) {
            while (inet4RouteAddress.hasNext()) {
                builder.addRoute(inet4RouteAddress.next().toIpPrefix())
            }
        } else if (options.inet4Address.hasNext()) {
            builder.addRoute(IpPrefix(InetAddress.getByName("0.0.0.0"), 0))
        }

        val inet6RouteAddress = options.inet6RouteAddress
        if (inet6RouteAddress.hasNext()) {
            while (inet6RouteAddress.hasNext()) {
                builder.addRoute(inet6RouteAddress.next().toIpPrefix())
            }
        } else if (options.inet6Address.hasNext()) {
            builder.addRoute(IpPrefix(InetAddress.getByName("::"), 0))
        }

        val inet4RouteExcludeAddress = options.inet4RouteExcludeAddress
        while (inet4RouteExcludeAddress.hasNext()) {
            builder.excludeRoute(inet4RouteExcludeAddress.next().toIpPrefix())
        }

        val inet6RouteExcludeAddress = options.inet6RouteExcludeAddress
        while (inet6RouteExcludeAddress.hasNext()) {
            builder.excludeRoute(inet6RouteExcludeAddress.next().toIpPrefix())
        }
    }

    private fun addLegacyRoutes(builder: Builder, options: TunOptions) {
        val inet4RouteRange = options.inet4RouteRange
        while (inet4RouteRange.hasNext()) {
            val route = inet4RouteRange.next()
            builder.addRoute(route.address(), route.prefix())
        }

        val inet6RouteRange = options.inet6RouteRange
        while (inet6RouteRange.hasNext()) {
            val route = inet6RouteRange.next()
            builder.addRoute(route.address(), route.prefix())
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN Control", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun showForegroundNotification(text: String) {
        val notification = buildNotification(text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("VPN Control")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setOngoing(true)
            .build()
    }

    private fun dumpFlags(networkInterface: NetworkInterface, hasInternet: Boolean): Int {
        var flags = 0
        if (hasInternet) {
            flags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING
        }
        if (networkInterface.isLoopback) {
            flags = flags or OsConstants.IFF_LOOPBACK
        }
        if (networkInterface.isPointToPoint) {
            flags = flags or OsConstants.IFF_POINTOPOINT
        }
        if (networkInterface.supportsMulticast()) {
            flags = flags or OsConstants.IFF_MULTICAST
        }
        return flags
    }

    private fun InterfaceAddress.toPrefixString(): String {
        val host = when (val address = address) {
            is Inet6Address -> address.hostAddress?.substringBefore('%').orEmpty()
            null -> ""
            else -> address.hostAddress.orEmpty()
        }
        return "$host/${networkPrefixLength.toInt()}"
    }

    private fun io.nekohasekai.libbox.RoutePrefix.toIpPrefix(): IpPrefix {
        return IpPrefix(InetAddress.getByName(address()), prefix())
    }

    private fun StringIterator.toList(): List<String> {
        val list = mutableListOf<String>()
        while (hasNext()) {
            list.add(next())
        }
        return list
    }

    private class StringListIterator(
        private val values: List<String>,
    ) : StringIterator {
        private var index = 0

        override fun hasNext(): Boolean = index < values.size

        override fun len(): Int = values.size

        override fun next(): String = values[index++]
    }

    private class NetworkInterfaceListIterator(
        private val values: List<BoxNetworkInterface>,
    ) : NetworkInterfaceIterator {
        private var index = 0

        override fun hasNext(): Boolean = index < values.size

        override fun next(): BoxNetworkInterface = values[index++]
    }

    companion object {
        const val ACTION_START = "com.kardinal.vpncontrol.START"
        const val ACTION_STOP = "com.kardinal.vpncontrol.STOP"
        private const val CHANNEL_ID = "vpn_control"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "AndroidVpnService"
    }
}
