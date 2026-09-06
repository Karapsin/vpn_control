package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeout
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopPendingConnectionCliTest {
    @Test
    fun asyncConnectRetrySharesOneRuntimeStartAndRemainsQueryable() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-async-connect")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val records = listOf("socks://127.0.0.1:1080#First").toDesktopLocationRecords(1)
        val runtime = RecordingRuntime { entered.complete(Unit); release.await() }
        val service = DesktopAppServiceFactory.createForTesting(
            store = DesktopStateStore(directory), runtimeController = runtime,
            initialWorkspace = DesktopWorkspace(PersistedState(
                appMode = AppMode.PROXY_ONLY, profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                savedLocations = records.map { it.rawLink }, currentLocations = records.map { it.rawLink },
                selectedProfileRawLink = records[0].rawLink, selectedProfileName = records[0].name,
                selectedProfileServer = records[0].server,
            ), records),
        )
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId,
        ))
        fun submit(request: ControlRequest): ControlResult = ControlProtocolCodec.decodeResult(
            DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(request), endpoint).message)
        try {
            var sent: ControlRequest? = null
            val lines = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs(arrayOf("--json", "--async", "on"), lines::add,
                requestCommand = {
                    sent = (it as DesktopCliCommand.ControlSubmit).request
                    DesktopActivationServer.requestCliCommand(it, endpoint)
                }, startHeadlessController = { error("Existing controller required") }))
            val request = requireNotNull(sent).copy(controllerId = owner.controllerId)
            val accepted = ControlProtocolCodec.decodeResult(lines.single())
            assertEquals(ControlCode.ACCEPTED, accepted.code)
            assertFalse(accepted.final)
            withTimeout(5_000) { entered.await() }
            val retry = submit(request)
            assertEquals(accepted.operationId, retry.operationId)
            assertFalse(retry.final)
            assertEquals(ControlCode.BUSY, submit(request.copy(requestId = "another-connect")).code)
            assertEquals(ControlCode.CONFLICT, submit(request.copy(command = ControlCommand(ControlOperationId.OFF))).code)
            assertEquals(ControlCode.OK, submit(ControlRequest("status", ControlCommand(ControlOperationId.STATUS),
                controllerId = owner.controllerId)).code)
            assertEquals(1, runtime.starts)
            release.complete(Unit)
            val completed = submit(request.copy(asynchronous = false))
            assertEquals(ControlCode.OK, completed.code)
            assertTrue(completed.final)
            assertEquals(accepted.operationId, completed.operationId)
            assertEquals(completed, submit(request))
            assertEquals(1, runtime.starts)
            assertEquals(1, owner.session.operationSnapshot().size)
            assertEquals(0, runtime.stops)
            assertTrue(service.shouldResumeConnectionOnLaunch())
        } finally {
            release.complete(Unit)
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun selectionIsPendingUntilExplicitRestartAndOnNeverRestarts() {
        val directory = Files.createTempDirectory("vpn-control-pending-cli")
        val records = listOf("socks://127.0.0.1:1080#First", "socks://127.0.0.2:1080#Second")
            .toDesktopLocationRecords(1)
        val runtime = RecordingRuntime()
        val service = DesktopAppServiceFactory.createForTesting(
            store = DesktopStateStore(directory), runtimeController = runtime,
            initialWorkspace = DesktopWorkspace(PersistedState(
                appMode = AppMode.PROXY_ONLY, profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
                savedLocations = records.map { it.rawLink }, currentLocations = records.map { it.rawLink },
                selectedProfileRawLink = records[0].rawLink, selectedProfileName = records[0].name,
                selectedProfileServer = records[0].server,
            ), records),
        )
        val endpoint = directory.resolve("activation.port")
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
        val session = DesktopHeadlessSession(scope, { service.state }, service::executeCliCommand, {},
            metadataProvider = service::controlMetadata, inspectStatus = service::controlSnapshot)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint, controllerId = session.controllerId,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Existing controller required") }) to lines.joinToString("\n")
            }
            assertEquals(1, invoke("restart").first)
            assertEquals(0, invoke("on").first)
            assertEquals(listOf("First"), runtime.names)
            assertEquals(ControlOperationId.ON, session.operationSnapshot().last().operation)
            fun jsonStatus(): ControlResult {
                val response = invoke("--json", "status")
                assertEquals(0, response.first, response.second)
                return com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(response.second)
            }
            val started = jsonStatus()
            assertEquals(started.data["selectedLocationId"], started.data["activeLocationId"])
            assertTrue(started.data["runtimeId"] is ControlValue.Text)
            assertTrue(started.data["runtimeStartedAt"] is ControlValue.IntegerValue)
            assertEquals(0, invoke("select", "Second").first)
            val pending = jsonStatus()
            assertTrue(pending.restartRequired)
            assertTrue(pending.data["selectedLocationId"] != pending.data["activeLocationId"])
            assertEquals(started.data["runtimeId"], pending.data["runtimeId"])
            assertEquals(started.data["runtimeStartedAt"], pending.data["runtimeStartedAt"])
            assertTrue(invoke("status").second.contains("active: \"First\""))
            assertTrue(invoke("status").second.contains("pending restart"))
            assertEquals(0, invoke("on").first)
            assertEquals(listOf("First"), runtime.names)
            assertEquals(started.data["runtimeId"], jsonStatus().data["runtimeId"])
            assertEquals(0, invoke("select", "First").first)
            assertFalse(invoke("status").second.contains("pending restart"))
            assertEquals(0, invoke("select", "Second").first)
            // Routing controls auto-save; DNS dialog text remains an uncommitted draft.
            service.setRoutingDirectDomainsDraft("committed.example")
            service.toggleDnsDialog()
            service.setDnsModeDraft(DnsMode.CUSTOM_DOH)
            service.setCustomDnsDraft("https://unsaved.example/dns-query")
            val committedDns = service.state.dnsSettings
            val jsonRestart = invoke("--json", "restart")
            assertEquals(0, jsonRestart.first, jsonRestart.second)
            assertEquals(ControlCode.OK, com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(jsonRestart.second).code)
            assertEquals(listOf("First", "Second"), runtime.names)
            val restarted = jsonStatus()
            assertTrue(started.data["runtimeId"] != restarted.data["runtimeId"])
            assertEquals(restarted.data["selectedLocationId"], restarted.data["activeLocationId"])
            assertFalse(restarted.restartRequired)
            assertTrue(runtime.rules.last().directDomainSuffixes.contains("committed.example"))
            assertEquals(committedDns, runtime.dns.last())
            assertFalse(invoke("status").second.contains("pending restart"))
            val jsonOff = invoke("--json", "off")
            assertEquals(0, jsonOff.first, jsonOff.second)
            assertEquals(ControlCode.OK, com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(jsonOff.second).code)
            assertEquals(1, runtime.stops)
            assertEquals(null, service.activeDesktopLocation())
            assertEquals(ControlValue.Null, jsonStatus().data["runtimeId"])
            assertFalse(service.shouldResumeConnectionOnLaunch())
        } finally {
            server.close()
            session.close()
            scope.coroutineContext[kotlinx.coroutines.Job]?.cancel()
            directory.toFile().deleteRecursively()
        }
    }
}

private class RecordingRuntime(private val beforeStart: suspend () -> Unit = {}) : DesktopRuntimeController {
    @Volatile var starts = 0
    val names = mutableListOf<String>()
    val rules = mutableListOf<RoutingRules>()
    val dns = mutableListOf<DnsSettings>()
    var stops = 0
    private var mode: AppMode? = null
    override suspend fun start(profile: ProxyProfile, routingRules: RoutingRules, dnsSettings: DnsSettings,
        appMode: AppMode, activeVerificationPort: Int?, homeSshRouteSettings: HomeSshRouteSettings): Result<DesktopRuntimeSession> {
        starts++
        beforeStart()
        names += profile.remarks
        rules += routingRules
        dns += dnsSettings
        mode = appMode
        return Result.success(DesktopRuntimeSession(appMode = appMode, listenPort = 1080, interfaceName = null,
            configJson = "{}", logFile = Path.of("synthetic.log"), processId = 1L))
    }
    override suspend fun stop(): Result<Unit> { stops++; mode = null; return Result.success(Unit) }
    override fun isRunning(): Boolean = mode != null
    override fun currentMode(): AppMode? = mode
    override fun currentPort(): Int? = 1080.takeIf { isRunning() }
}
