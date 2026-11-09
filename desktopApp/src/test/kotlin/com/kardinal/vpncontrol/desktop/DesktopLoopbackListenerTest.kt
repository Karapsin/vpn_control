package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.CandidateCountryResolver
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.UserCountryResolver
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketAddress
import java.net.SocketException
import java.net.SocketImpl
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.system.exitProcess
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Windows Defender Firewall asks to allow network access when a program without a rule listens
 * beyond the loopback. On native operation b3d71dca, PickerHost's FirewallNotificationDialogServer
 * started 1.3 s after a proxy `on` and 9 s before sing-box: the listener was the app's own
 * free-port probe, `ServerSocket(0)`. The prompt is native; this test records the address of every
 * server socket the app binds on its runtime, direct-probe, validation, SSH-bootstrap and control
 * paths. A child JVM installs a recording server-socket implementation, so no OS socket opens and
 * the JVM-wide factory never reaches other tests.
 */
class DesktopLoopbackListenerTest {
    @Test fun everyListenerAndPortProbeOfTheAppBindsTheLoopbackOnly() {
        val directory = Files.createTempDirectory("vpn-control-loopback-binds")
        try {
            val output = directory.resolve("child-output.txt")
            val javaName = if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java"
            val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
            val builder = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", javaName).toString(),
                "-Djava.awt.headless=true", "-Duser.home=${directory.resolve("home")}", "-cp", classpath,
                DesktopLoopbackBindRecorder::class.java.name, directory.toString())
                .redirectErrorStream(true).redirectOutput(output.toFile())
            // No sing-box can resolve, so every path stops after its port probe and starts no runtime.
            // Windows names are case-insensitive, but this map is not.
            builder.environment().keys.removeIf { it.equals("PATH", true) || it.equals("VPN_CONTROL_SING_BOX", true) }
            builder.environment()["PATH"] = Files.createDirectory(directory.resolve("empty-path")).toString()
            val process = builder.start()
            val finished = process.waitFor(120, TimeUnit.SECONDS)
            if (!finished) {
                process.destroyForcibly()
                process.waitFor(10, TimeUnit.SECONDS)
            }
            val text = Files.readString(output)
            println(text) // The bind record stays in the test report.
            assertTrue(finished && process.exitValue() == 0 && "done" in text.lines(), "Recording child failed:\n$text")

            val lines = text.lines().map { it.split('\t') }
            val binds = lines.filter { it[0] == "bind" }
                .map { Bind(it[1], it[2], it[3].toBooleanStrict(), it[4].toInt(), it[5].toInt(), it[6]) }
            val ports = lines.filter { it[0] == "port" }.map { it[1] to it[2].toInt() }
            for (scenario in listOf("runtime-on", "direct-probe", "validation", "ssh-bootstrap", "control")) {
                assertTrue(binds.any { it.scenario == scenario }, "$scenario bound no server socket:\n$text")
            }
            // The runtime's two inbounds and the control endpoint use ports that a recorded bind handed out.
            assertEquals(2, ports.count { it.first == "runtime-on" }, text)
            assertEquals(1, ports.count { it.first == "control" }, text)
            for ((scenario, port) in ports) {
                assertTrue(binds.any { it.scenario == scenario && it.requested == 0 && it.assigned == port },
                    "$scenario used port $port that no recorded bind handed out:\n$text")
            }
            val beyondLoopback = binds.filterNot(Bind::loopback)
            assertTrue(beyondLoopback.isEmpty(), "Server sockets bound beyond the loopback:\n" +
                beyondLoopback.joinToString("\n") { "${it.scenario}: ${it.address} port ${it.requested} at ${it.site}" })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private data class Bind(val scenario: String, val address: String, val loopback: Boolean,
                            val requested: Int, val assigned: Int, val site: String)
}

/** The child of [DesktopLoopbackListenerTest]: one tab-separated line per bind, port used and outcome. */
object DesktopLoopbackBindRecorder {
    @Volatile private var current = "startup"
    private val nextPort = AtomicInteger(47_000)

    @JvmStatic fun main(arguments: Array<String>) {
        val directory = Path.of(arguments.single())
        @Suppress("DEPRECATION")
        ServerSocket.setSocketFactory { DesktopLoopbackBindRecordingImpl() }
        DesktopWorkspacePaths.configure(DesktopWorkspaceInvocation(emptyList(), directory.resolve("workspace")))
        val resolver = DesktopSingBoxResolver(directory.resolve("tools"), osNameOverride = "none")
        check(resolver.resolve() == null) { "A sing-box resolved; the recording child starts no runtime" }
        val profile = LocationConfigs.decodeStoredLocation("socks://127.0.0.1:1080#Fixture")

        scenario("runtime-on") {
            val manager = DesktopProxyRuntimeManager(runtimeConfigStore = DesktopLoopbackMemoryStore(),
                baseDir = directory.resolve("runtime"), singBoxResolver = resolver)
            val result = runBlocking {
                manager.start(profile, RoutingRules(), DnsSettings(), AppMode.PROXY_ONLY, null, HomeSshRouteSettings())
            }
            emit("outcome", result.exceptionOrNull()?.let(::describe) ?: "started")
            Json.parseToJsonElement(checkNotNull(manager.lastAttemptedConfigJson())).jsonObject.getValue("inbounds").jsonArray
                .forEach { emit("port", it.jsonObject.getValue("listen_port").jsonPrimitive.int.toString()) }
            runBlocking { manager.stop() }
        }
        scenario("direct-probe") {
            runBlocking { DesktopDirectProbeProxy(directory.resolve("direct"), resolver).useProxy { "unreachable" } }
        }
        scenario("validation") {
            val runtime = DesktopProxyValidationRuntime(directory.resolve("validation"), resolver,
                UserCountryResolver { null }, CandidateCountryResolver { null })
            val result = runBlocking {
                runtime.benchmarkPreflightCandidate(PreflightResult(profile, 1.0, "fixture"), DnsSettings(), BenchmarkUrls())
            }
            emit("outcome", result.fold({ it.detail }, ::describe))
        }
        scenario("ssh-bootstrap") {
            val credentials = DesktopHomeSshCredentialStore(directory.resolve("ssh"))
            credentials.importPrivateKey("-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n")
            val settings = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture")
            val client = DesktopSubscriptionDownloadClient(stateProvider = { PersistedState(homeSshRouteSettings = settings) },
                credentialStore = credentials, bootstrapBaseDir = directory.resolve("bootstrap"), singBoxResolver = resolver)
            runBlocking { client.fetch("https://subscription.example.test/", "") }
        }
        scenario("control") {
            val portFile = directory.resolve("control").resolve("activation.port")
            val server = checkNotNull(DesktopActivationServer.start(onShowWindow = { DesktopActivationShowResult.SHOWN },
                portFile = portFile))
            try {
                emit("port", DesktopControlEndpoint.read(portFile).port.toString())
            } finally {
                server.close()
            }
        }
        println("done")
        System.out.flush()
        exitProcess(0)
    }

    /** Each path ends without sing-box; its expected failure is printed, not thrown. */
    private fun scenario(name: String, body: () -> Unit) {
        current = name
        try {
            body()
        } catch (failure: Exception) {
            emit("outcome", describe(failure))
        }
    }

    private fun describe(failure: Throwable) = "${failure::class.simpleName}: ${failure.message?.lineSequence()?.first()}"

    private fun emit(kind: String, value: String) = println("$kind\t$current\t$value")

    internal fun bound(host: InetAddress?, requested: Int, assigned: Int) {
        val site = Throwable().stackTrace.firstOrNull {
            it.className.startsWith("com.kardinal.vpncontrol.") &&
                !it.className.startsWith("com.kardinal.vpncontrol.desktop.DesktopLoopback")
        }?.let { "${it.className.substringAfterLast('.')}.${it.methodName}(${it.fileName}:${it.lineNumber})" }
        emit("bind", "${host?.hostAddress}\t${host?.isLoopbackAddress == true}\t$requested\t$assigned\t$site")
    }

    internal fun nextPort(): Int = nextPort.incrementAndGet()
}

/** Records each server-socket bind and hands out a port; it opens no OS socket and accepts nothing. */
private class DesktopLoopbackBindRecordingImpl : SocketImpl() {
    override fun create(stream: Boolean) {}
    override fun bind(host: InetAddress?, port: Int) {
        address = host
        localport = if (port == 0) DesktopLoopbackBindRecorder.nextPort() else port
        DesktopLoopbackBindRecorder.bound(host, port, localport)
    }
    override fun listen(backlog: Int) {}
    override fun accept(s: SocketImpl?) { throw SocketException("The recording socket accepts no connection") }
    override fun connect(host: String?, port: Int) { throw SocketException("The recording socket does not connect") }
    override fun connect(address: InetAddress?, port: Int) { throw SocketException("The recording socket does not connect") }
    override fun connect(address: SocketAddress?, timeout: Int) { throw SocketException("The recording socket does not connect") }
    override fun getInputStream(): InputStream = throw SocketException("The recording socket has no stream")
    override fun getOutputStream(): OutputStream = throw SocketException("The recording socket has no stream")
    override fun available(): Int = 0
    override fun close() {}
    override fun sendUrgentData(data: Int) { throw SocketException("The recording socket sends nothing") }
    override fun setOption(optID: Int, value: Any?) {}
    override fun getOption(optID: Int): Any? = null
}

private class DesktopLoopbackMemoryStore : RuntimeConfigStore {
    @Volatile private var config: String? = null
    override suspend fun readRuntimeConfig(): String? = config
    override suspend fun writeRuntimeConfig(configJson: String) { config = configJson }
    override suspend fun clearRuntimeConfig() { config = null }
}
