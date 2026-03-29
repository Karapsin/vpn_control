package com.kardinal.vpncontrol.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.system.OsConstants
import android.util.Base64
import com.kardinal.vpncontrol.data.DiagnosticsLogger
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.LocalDNSTransport
import io.nekohasekai.libbox.NetworkInterface as BoxNetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import java.net.Inet6Address
import java.net.NetworkInterface
import java.security.KeyStore

class LibboxValidationPlatform(
    private val context: Context,
    private val logPrefix: String,
) : PlatformInterface {
    private val connectivity by lazy { context.getSystemService(ConnectivityManager::class.java) }

    override fun autoDetectInterfaceControl(fd: Int) {
    }

    override fun clearDNSCache() {
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
    }

    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String,
        sourcePort: Int,
        destinationAddress: String,
        destinationPort: Int,
    ): Int {
        error("Connection owner lookup is unavailable in validation mode")
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
                addresses = ValidationStringIterator(networkInterface.interfaceAddresses.map { it.toPrefixString() })
                dnsServer = ValidationStringIterator(linkProperties.dnsServers.mapNotNull { it.hostAddress?.substringBefore('%') })
                type = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> io.nekohasekai.libbox.Libbox.InterfaceTypeWIFI.toInt()
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> io.nekohasekai.libbox.Libbox.InterfaceTypeCellular.toInt()
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> io.nekohasekai.libbox.Libbox.InterfaceTypeEthernet.toInt()
                    else -> io.nekohasekai.libbox.Libbox.InterfaceTypeOther.toInt()
                }
                flags = dumpFlags(networkInterface, capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
                metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
            interfaces.add(boxInterface)
        }
        return ValidationNetworkInterfaceIterator(interfaces)
    }

    override fun includeAllNetworks(): Boolean = false

    override fun localDNSTransport(): LocalDNSTransport = NoopLocalDnsTransport

    override fun openTun(options: TunOptions): Int {
        error("Tun is unavailable in validation mode")
    }

    override fun packageNameByUid(uid: Int): String = ""

    override fun readWIFIState(): WIFIState? = null

    override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {
        DiagnosticsLogger.append(
            context,
            "$logPrefix notification: ${notification.title.ifBlank { "Validation" }} ${notification.body}",
        )
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) {
    }

    override fun systemCertificates(): StringIterator {
        val certificates = mutableListOf<String>()
        runCatching {
            val keyStore = KeyStore.getInstance("AndroidCAStore")
            keyStore.load(null, null)
            val aliases = keyStore.aliases()
            while (aliases.hasMoreElements()) {
                val cert = keyStore.getCertificate(aliases.nextElement()) ?: continue
                val body = Base64.encodeToString(cert.encoded, Base64.NO_WRAP)
                certificates.add("-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----")
            }
        }
        return ValidationStringIterator(certificates)
    }

    override fun uidByPackageName(packageName: String): Int {
        error("Package UID lookup is unavailable in validation mode")
    }

    override fun underNetworkExtension(): Boolean = false

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = false

    override fun useProcFS(): Boolean = false

    override fun writeLog(message: String) {
        DiagnosticsLogger.append(context, "$logPrefix libbox: $message")
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

    private fun java.net.InterfaceAddress.toPrefixString(): String {
        val host = when (val address = address) {
            is Inet6Address -> address.hostAddress?.substringBefore('%').orEmpty()
            null -> ""
            else -> address.hostAddress.orEmpty()
        }
        return "$host/${networkPrefixLength.toInt()}"
    }
}

private object NoopLocalDnsTransport : LocalDNSTransport {
    override fun exchange(ctx: io.nekohasekai.libbox.ExchangeContext, message: ByteArray) {
        ctx.errorCode(2)
    }

    override fun lookup(ctx: io.nekohasekai.libbox.ExchangeContext, network: String, domain: String) {
        ctx.errorCode(2)
    }

    override fun raw(): Boolean = false
}

private class ValidationStringIterator(
    private val values: List<String>,
) : StringIterator {
    private var index = 0

    override fun hasNext(): Boolean = index < values.size

    override fun len(): Int = values.size

    override fun next(): String = values[index++]
}

private class ValidationNetworkInterfaceIterator(
    private val values: List<BoxNetworkInterface>,
) : NetworkInterfaceIterator {
    private var index = 0

    override fun hasNext(): Boolean = index < values.size

    override fun next(): BoxNetworkInterface = values[index++]
}
