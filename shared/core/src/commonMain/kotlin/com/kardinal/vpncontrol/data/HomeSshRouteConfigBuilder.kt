package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.HomeSshRouteLogic
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class HomeSshRouteRuntimeOptions(
    val settings: HomeSshRouteSettings,
    val privateKeyPath: String,
) {
    fun validated(): HomeSshRouteRuntimeOptions {
        val normalized = HomeSshRouteLogic.validate(
            settings = settings,
            credentialAvailable = privateKeyPath.isNotBlank(),
        ).getOrThrow()
        return copy(settings = normalized, privateKeyPath = privateKeyPath.trim())
    }
}

object HomeSshRouteConfigBuilder {
    const val SSH_OUTBOUND_TAG = "vpn-control-home-ssh"
    const val HOME_EGRESS_TAG = "vpn-control-home-egress"
    const val MANAGEMENT_INBOUND_TAG = "vpn-control-management"

    fun buildOutbounds(options: HomeSshRouteRuntimeOptions): List<JsonObject> {
        val validated = options.validated()
        val settings = validated.settings
        return listOf(
            buildJsonObject {
                put("type", "socks")
                put("tag", HOME_EGRESS_TAG)
                put("server", "127.0.0.1")
                put("server_port", settings.relayPort)
                put("version", "5")
                put(
                    "udp_over_tcp",
                    buildJsonObject {
                        put("enabled", true)
                        put("version", 2)
                    },
                )
                put("detour", SSH_OUTBOUND_TAG)
            },
            buildJsonObject {
                put("type", "ssh")
                put("tag", SSH_OUTBOUND_TAG)
                put("server", settings.host)
                put("server_port", settings.port)
                put("user", settings.user)
                put("private_key_path", validated.privateKeyPath)
                put("host_key", JsonArray(settings.hostKeys.map(::JsonPrimitive)))
                put("domain_resolver", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
            },
        )
    }

    fun buildBootstrapProxyConfig(
        options: HomeSshRouteRuntimeOptions,
        listenPort: Int,
    ): JsonObject {
        require(listenPort in 1..65535) { "Management proxy port must be between 1 and 65535" }
        return buildJsonObject {
            put("log", buildJsonObject { put("level", "warning") })
            put(
                "dns",
                buildJsonObject {
                    put(
                        "servers",
                        buildJsonArray {
                            add(
                                buildJsonObject {
                                    put("type", "udp")
                                    put("tag", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
                                    put("server", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER)
                                    put("server_port", 53)
                                },
                            )
                        },
                    )
                },
            )
            put(
                "inbounds",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "mixed")
                            put("tag", MANAGEMENT_INBOUND_TAG)
                            put("listen", "127.0.0.1")
                            put("listen_port", listenPort)
                        },
                    )
                },
            )
            put(
                "outbounds",
                JsonArray(
                    buildOutbounds(options) + buildJsonObject {
                        put("type", "direct")
                        put("tag", "direct")
                    },
                ),
            )
            put(
                "route",
                buildJsonObject {
                    put("auto_detect_interface", true)
                    put("final", HOME_EGRESS_TAG)
                },
            )
        }
    }
}
