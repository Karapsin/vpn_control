package com.kardinal.vpncontrol

import androidx.datastore.core.DataStoreFactory
import androidx.datastore.preferences.core.*
import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import java.io.Closeable
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.*
import org.junit.Assert.*

/** Real serializer, DataStore transaction, owner, ledger, jobs and runtime receipts.
 * Only Android consent/foreground, bundled native execution and share UI are seams.
 */
internal class AndroidGuiOwnerActionFixture(running: Boolean = false) : Closeable {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
    private val directory = Files.createTempDirectory("gui-owner-actions-").toFile()
    private val file = File(directory, "configuration.preferences_pb")
    private val serializer = AndroidPreferencesSerializer(directory.toPath())
    private val store = DataStoreFactory.create(serializer = serializer, scope = scope) { file }
    private val modeKey = stringPreferencesKey("app_mode")
    private val selectedKey = stringPreferencesKey("selected_profile_json")
    private val runtimeKey = stringPreferencesKey("runtime_config_json")
    private val summaryKey = stringPreferencesKey("last_benchmark_summary")
    private val sourceKey = stringPreferencesKey("selected_profile_source_url")
    val configuration = AndroidConfigurationStore(store, { prefs ->
        val encoded = prefs[selectedKey].orEmpty()
        val profile = encoded.takeIf(String::isNotBlank)?.let(LocationConfigs::decodeStoredLocation)
        PersistedState(appMode = prefs[modeKey]?.let(AppMode::valueOf) ?: AppMode.VPN,
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
            selectedProfileName = profile?.remarks.orEmpty(), selectedProfileServer = profile?.server.orEmpty(),
            selectedProfileRawLink = profile?.rawLink.orEmpty(), selectedProfileJson = encoded,
            runtimeConfigJson = prefs[runtimeKey].orEmpty(), selectedProfileSourceUrl = prefs[sourceKey].orEmpty(),
            lastBenchmarkSummary = prefs[summaryKey].orEmpty())
    }, "owner")
    val observer = AndroidRuntimeObserver(initiallyStopped = !running)
    val jobs = AndroidCommandJobs(scope)
    val runtimeCommands = AndroidRuntimeCommands()
    val interactions = AndroidControlInteractions("owner")
    val controller = MainController(MainUiState(isVpnRunning = running, hasVpnPermission = true))
    val statuses = mutableListOf<String>()
    val requests = mutableListOf<ControlRequest>()
    val results = mutableListOf<ControlResult>()
    val shares = mutableListOf<String>()
    val frontendJobs = mutableListOf<Job>()
    var frontendLaunch: (suspend () -> Unit) -> Unit = { runBlocking { it() } }
    var starts = 0
    var stops = 0
    var persists = 0
    var reports = 0
    var foreground = true
    var vpnPrepared = true
    var loseResponse = false
    var reportFailure = false
    var shareFailure = false
    var shareThrows = false
    var failPersist = false
    var nativeFailure: Exception? = null
    var nativeGate: CompletableDeferred<Unit>? = null
    var reportGate: CompletableDeferred<Unit>? = null
    var beforeExecute: suspend () -> Unit = {}
    var busy = false
    val report = "OWNER-SANITIZED-REPORT-✓"
    init { if (running) observer.started(Any(), AppMode.VPN, "inert-live-A",
        ControlRuntimeConfiguration.committed(controller.currentState())) }

    private fun withSelection(state: PersistedState, selection: ProfileSelection) = state.copy(
        selectedProfileName = selection.profile.remarks, selectedProfileServer = selection.profile.server,
        selectedProfileRawLink = selection.profile.rawLink, selectedProfileJson = LocationConfigs.encodeStoredLocation(selection.profile),
        runtimeConfigJson = selection.runtimeConfigJson, selectedProfileSourceUrl = selection.sourceUrl,
        lastBenchmarkSummary = selection.benchmark.detail)

    suspend fun persist(selection: ProfileSelection) {
        if (failPersist) throw java.io.IOException("PRIVATE persisted response failure")
        configuration.edit { prefs ->
            prefs[selectedKey] = LocationConfigs.encodeStoredLocation(selection.profile)
            prefs[runtimeKey] = selection.runtimeConfigJson
            prefs[sourceKey] = selection.sourceUrl
            prefs[summaryKey] = selection.benchmark.detail
            persists++
        }
    }

    suspend fun start(selection: ProfileSelection, eligible: () -> Boolean): Result<Unit> {
        val ticket = runtimeCommands.register(AndroidRuntimeAction.START, selection.runtimeConfigJson)
        check(runtimeCommands.claim(ticket.id, AndroidRuntimeAction.START, selection.runtimeConfigJson))
        starts++
        nativeGate?.await()
        val outcome = nativeFailure?.let { Result.failure<Unit>(it) } ?: if (!eligible())
            Result.failure(IllegalStateException("PRIVATE no longer eligible")) else {
            val actual = withSelection(configuration.snapshot().value, selection)
            observer.started(Any(), actual.appMode, selection.runtimeConfigJson,
                ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), actual)))
            Result.success(Unit)
        }
        runtimeCommands.complete(ticket.id, outcome)
        return runtimeCommands.await(ticket, 10_000)
    }
    suspend fun stop(): Result<Unit> {
        val ticket = runtimeCommands.register(AndroidRuntimeAction.STOP)
        check(runtimeCommands.claim(ticket.id, AndroidRuntimeAction.STOP))
        stops++
        nativeGate?.await()
        val outcome = nativeFailure?.let { Result.failure<Unit>(it) } ?: Result.success(Unit).also { observer.resetCompleted(true) }
        runtimeCommands.complete(ticket.id, outcome)
        return runtimeCommands.await(ticket, 10_000)
    }
    suspend fun collectReport(state: PersistedState): String {
        // The owner captured the real committed state before entering this OS-log seam.
        assertEquals(configuration.snapshot().value, state)
        reports++
        reportGate?.await()
        if (reportFailure) throw java.io.IOException("PRIVATE diagnostic failure")
        return report
    }
    suspend fun shareReport(content: String): Result<String> {
        shares += content
        val written = writeAndroidDiagnosticsReport(directory, content)
        assertArrayEquals(content.toByteArray(Charsets.UTF_8), written.readBytes())
        if (shareThrows) throw java.io.IOException("PRIVATE thrown sharing failure")
        return if (shareFailure) Result.failure(java.io.IOException("PRIVATE sharing failure")) else Result.success("presentation")
    }
    val connection = AndroidConnectionControl("owner", configuration::snapshot, { observer.state.value },
        { foreground }, { vpnPrepared }, interactions, { Result.success(selection()) }, {}, ::start, ::persist, observer::pendingRestart)
    val owner = AndroidSettingsControl("owner", scope, configuration::snapshot,
        { _, _, _ -> error("No settings write is expected") }, {}, observer::pendingRestart,
        mutationJobs = jobs, busy = { jobs.busy.value },
        off = AndroidOffControl("owner", configuration::snapshot, { observer.state.value }, ::stop, observer::pendingRestart),
        connection = connection, diagnosticsExport = ::collectReport)

    suspend fun execute(request: ControlRequest): ControlResult {
        // Production wire codecs ensure assertions concern the actual typed envelope.
        val decoded = ControlDocumentCodec.decodeRequest(ControlDocumentCodec.encodeRequest(request))
        requests += decoded
        beforeExecute().also { beforeExecute = {} }
        val result = ControlDocumentCodec.decodeResult(ControlDocumentCodec.encodeResult(owner.execute(decoded)))
        results += result
        if (loseResponse) { loseResponse = false; throw java.io.IOException("PRIVATE lost owner response") }
        return result
    }
    fun operations(): List<ControlValue> = runBlocking {
        val result = owner.execute(ControlRequest(java.util.UUID.randomUUID().toString(),
            ControlCommand(ControlOperationId.OPERATIONS_LIST), controllerId = "owner"))
        (result.data.getValue("operations") as ControlValue.ArrayValue).values
    }
    fun status(id: String, wait: Boolean = false): ControlResult = runBlocking {
        owner.execute(ControlRequest(java.util.UUID.randomUUID().toString(), ControlCommand(
            if (wait) ControlOperationId.OPERATIONS_WAIT else ControlOperationId.OPERATIONS_STATUS,
            mapOf("id" to ControlValue.Text(id))), controllerId = "owner"))
    }
    fun snapshot() = runBlocking { configuration.snapshot() }
    fun changeMode(mode: AppMode) = runBlocking { configuration.edit { it[modeKey] = mode.name } }
    fun coldReadSelectedProfile(): String = runBlocking {
        file.inputStream().use { AndroidPreferencesSerializer(directory.toPath()).readFrom(it)[selectedKey].orEmpty() }
    }
    fun launch(block: suspend () -> Unit) = frontendLaunch(block)

    // The RED runner substitutes only these constructor bindings. The authentic
    // unfixed service and lifecycle bodies remain byte equal to the beforeimages.
    fun connectionService() = AndroidConnectionActionsService(controller, { observer.state.value }, ::launch,
        configuration::snapshot, ::execute, { statuses += it })
    fun diagnosticsService() = AndroidDiagnosticsActionsService(::launch, { busy = it }, { statuses += it },
        configuration::snapshot, ::execute, ::shareReport)

    fun legacyLifecycle() = AndroidConnectionLifecycleService({ controller.currentState() }, controller::update,
        { busy = it }, { statuses += it }, { configuration.snapshot().value }, { _, _ -> },
        { Result.success(selection()) }, ::persist, { Result.success(selection()) },
        { start(it) { true } }, ::stop)
    suspend fun legacyDiagnosticsExport(): Result<String> = runCatching {
        shareReport(collectReport(configuration.snapshot().value)).getOrThrow()
    }
    override fun close() {
        runBlocking { requireNotNull(scope.coroutineContext[Job]).cancelAndJoin() }
        assertFalse(jobs.busy.value)
        check(directory.deleteRecursively())
    }
    companion object {
        fun selection(): ProfileSelection {
            val profile = ProxyProfile(protocol = ProxyProtocol.SOCKS, remarks = "fixture", server = "127.0.0.1", serverPort = 1234,
                network = "tcp", flow = "", security = "", sni = "", fingerprint = "", publicKey = "", shortId = "",
                path = "", hostHeader = "", serviceName = "", headerType = "", rawLink = "socks://127.0.0.1:1234")
            return ProfileSelection(profile, ProfileBenchmark(profile, "ok", "ok", 1.0, 1.0, 1.0, "fixture"), "{}")
        }
    }
}
