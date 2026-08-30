package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import java.net.URI

internal enum class SecureDnsTransport {
    HTTPS,
    TLS,
}

internal data class SecureDnsEndpoint(
    val transport: SecureDnsTransport,
    val server: String,
    val serverPort: Int,
    val path: String = "",
    val normalized: String,
) {
    val requiresBootstrap: Boolean
        get() = !server.isIpLiteral()
}

object SecureDnsEndpointParser {
    const val AUTOMATIC_DOH_ENDPOINT = "https://1.1.1.1/dns-query"

    fun normalize(settings: DnsSettings): Result<DnsSettings> = runCatching {
        when (settings.mode) {
            DnsMode.AUTOMATIC -> settings.copy(endpoint = "")
            DnsMode.CUSTOM_DOH, DnsMode.CUSTOM_DOT -> {
                val endpoint = parse(settings)
                settings.copy(endpoint = endpoint.normalized, legacyRawAddress = "")
            }
        }
    }

    internal fun resolve(settings: DnsSettings): SecureDnsEndpoint {
        return when (settings.mode) {
            DnsMode.AUTOMATIC -> parseUri(AUTOMATIC_DOH_ENDPOINT, DnsMode.CUSTOM_DOH)
            DnsMode.CUSTOM_DOH, DnsMode.CUSTOM_DOT -> parseUri(settings.endpoint.trim(), settings.mode)
        }
    }

    private fun parse(settings: DnsSettings): SecureDnsEndpoint {
        require(settings.endpoint.isNotBlank()) { "Secure DNS endpoint is required" }
        return parseUri(settings.endpoint.trim(), settings.mode)
    }

    private fun parseUri(raw: String, mode: DnsMode): SecureDnsEndpoint {
        val uri = URI(raw)
        require(uri.rawUserInfo == null) { "Secure DNS endpoint must not contain user information" }
        require(uri.rawFragment == null) { "Secure DNS endpoint must not contain a fragment" }
        require(uri.rawQuery == null) { "Secure DNS endpoint must not contain a query string" }
        val host = uri.host?.trim().orEmpty()
        require(host.isNotBlank()) { "Secure DNS endpoint must contain a host" }
        val explicitPort = uri.port
        require(explicitPort == -1 || explicitPort in 1..65535) { "Secure DNS endpoint port is invalid" }

        return when (mode) {
            DnsMode.AUTOMATIC -> error("Automatic DNS does not accept a custom URI")
            DnsMode.CUSTOM_DOH -> {
                require(uri.scheme.equals("https", ignoreCase = true)) { "Custom DoH endpoint must use https://" }
                val path = uri.rawPath?.takeIf(String::isNotBlank) ?: "/dns-query"
                require(path.startsWith('/')) { "Custom DoH endpoint path is invalid" }
                val port = explicitPort.takeIf { it != -1 } ?: 443
                SecureDnsEndpoint(
                    transport = SecureDnsTransport.HTTPS,
                    server = host,
                    serverPort = port,
                    path = path,
                    normalized = buildUri("https", host, port, 443, path),
                )
            }
            DnsMode.CUSTOM_DOT -> {
                require(uri.scheme.equals("tls", ignoreCase = true)) { "Custom DoT endpoint must use tls://" }
                require(uri.rawPath.isNullOrBlank()) { "Custom DoT endpoint must not contain a path" }
                val port = explicitPort.takeIf { it != -1 } ?: 853
                SecureDnsEndpoint(
                    transport = SecureDnsTransport.TLS,
                    server = host,
                    serverPort = port,
                    normalized = buildUri("tls", host, port, 853, ""),
                )
            }
        }
    }

    private fun buildUri(scheme: String, host: String, port: Int, defaultPort: Int, path: String): String {
        return URI(scheme, null, host, port.takeUnless { it == defaultPort } ?: -1, path, null, null).toASCIIString()
    }

}

private fun String.isIpLiteral(): Boolean {
    if (contains(':')) return matches(Regex("[0-9a-fA-F:]+"))
    val parts = split('.')
    return parts.size == 4 && parts.all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }
}
