@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.SingBoxRouteDnsBuilder
import java.io.IOException
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** A short-lived direct proxy hosted in the only process exempt from the active desktop TUN. */
internal class DesktopDirectProbeProxy(
    private val baseDir: Path,
    private val singBoxResolver: DesktopSingBoxResolver,
) {
    suspend fun <T> useProxy(block: suspend (Int) -> T): T {
        Files.createDirectories(baseDir)
        val port = ServerSocket(0).use { it.localPort }
        val configFile = Files.createTempFile(baseDir, "direct-probe-", ".json")
        val logFile = Files.createTempFile(baseDir, "direct-probe-", ".log")
        val sourceBinary = singBoxResolver.resolve() ?: error(singBoxResolver.missingMessage())
        val probeBinary = prepareDirectProbeSingBoxExecutable(sourceBinary.path, baseDir)
        var process: Process? = null
        try {
            Files.writeString(configFile, directProxyConfig(port))
            process = ProcessBuilder(probeBinary.toString(), "run", "-c", configFile.toString())
                .directory(baseDir.toFile())
                .redirectErrorStream(true)
                .redirectOutput(logFile.toFile())
                .start()
            require(waitForPort(process, port)) { "Direct probe proxy did not become ready" }
            return block(port)
        } finally {
            process?.destroy()
            if (process?.waitFor(2, TimeUnit.SECONDS) == false) process?.destroyForcibly()
            runCatching { Files.deleteIfExists(configFile) }
            runCatching { Files.deleteIfExists(logFile) }
        }
    }

    private suspend fun waitForPort(process: Process?, port: Int): Boolean {
        repeat(30) {
            if (process?.isAlive != true) return false
            try {
                Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300) }
                return true
            } catch (_: IOException) {
                delay(100)
            }
        }
        return false
    }

    private fun directProxyConfig(port: Int): String {
        val root = buildJsonObject {
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
                    put("final", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
                },
            )
            put(
                "inbounds",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "mixed")
                            put("tag", "direct-probe-in")
                            put("listen", "127.0.0.1")
                            put("listen_port", port)
                        },
                    )
                },
            )
            put(
                "outbounds",
                buildJsonArray {
                    add(
                        buildJsonObject {
                            put("type", "direct")
                            put("tag", "direct")
                            put("domain_resolver", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
                        },
                    )
                },
            )
            put(
                "route",
                buildJsonObject {
                    put("auto_detect_interface", true)
                    put("default_domain_resolver", SingBoxRouteDnsBuilder.BOOTSTRAP_DNS_SERVER_TAG)
                    put("final", "direct")
                },
            )
        }
        return Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), root)
    }
}
