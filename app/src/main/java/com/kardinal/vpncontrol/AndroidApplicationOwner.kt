package com.kardinal.vpncontrol

import android.content.Context
import com.kardinal.vpncontrol.data.AppRepository
import com.kardinal.vpncontrol.data.BenchmarkOrchestrator
import com.kardinal.vpncontrol.data.DiagnosticsExporter
import com.kardinal.vpncontrol.data.InstalledAppsCatalog
import com.kardinal.vpncontrol.data.ProfileStorage
import com.kardinal.vpncontrol.data.SubscriptionRefreshScheduler
import com.kardinal.vpncontrol.data.VpnManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** One dependency graph per Android application process, shared by GUI and refresh work. */
internal class AndroidApplicationOwner(context: Context) {
    private val appContext = context.applicationContext
    val storage = ProfileStorage(appContext) { authoritativeRuntimeRunning() }
    val subscriptionRefreshScheduler = SubscriptionRefreshScheduler(appContext) { storage.configurationSnapshot().value }
    val directDomainRuleSets by lazy { com.kardinal.vpncontrol.data.AndroidDirectDomainRuleSetStore(
        java.io.File(appContext.filesDir, "runtime-rule-sets")) }
    fun pruneDirectDomainRuleSets(committedRuntimeJson: String) {
        val observed = runtimeObserver.state.value
        if (observed.knowledge != AndroidRuntimeKnowledge.STOPPED) return
        // Failure to inspect recovery inputs retains resources; it never licenses deletion.
        runCatching {
            val paths = buildSet {
                directDomainRuleSets.pathFromConfig(committedRuntimeJson)?.let(::add)
                val file = storage.runtimeConfigFile()
                if (file.exists()) directDomainRuleSets.pathFromConfig(file.readText())?.let(::add)
            }
            if (runtimeObserver.state.value == observed) directDomainRuleSets.prune(paths)
        }
    }
    val orchestrator = BenchmarkOrchestrator(appContext, storage)
    val repository = AppRepository(storage, orchestrator, subscriptionRefreshScheduler) { authoritativeRuntimeRunning() }
    val vpnManager = VpnManager(appContext, storage)
    val diagnosticsExporter = DiagnosticsExporter(appContext, storage)
    val installedAppsCatalog = InstalledAppsCatalog(appContext)
    val commands = AndroidCommandJobs()
    val controlTransfers = AndroidControlTransfers()
    val controlDocuments by lazy {
        AndroidControlDocuments(com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id,
            { AndroidControlTransferSpool.create(appContext.cacheDir.toPath()) })
    }
    // Manifest keeps this application/provider/VPN service in one process. The only
    // Libbox.newService call is AndroidVpnService.startVpn, which obtains owner.storage
    // before constructing a native handle. First owner construction therefore proves
    // no owned native runtime exists yet, including before a later START_STICKY restart.
    val runtimeObserver = AndroidRuntimeObserver(initiallyStopped = true)
    val preparedConnections = AndroidPreparedConnections()
    val runtimeCommands = AndroidRuntimeCommands()
    val retainedRuntimeServices = AndroidRetainedRuntimeServices()
    val foreground = AndroidForegroundState(appContext as android.app.Application)
    val interactions = AndroidControlInteractions(com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id)
    val connectionControl = AndroidConnectionControl(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, storage::configurationSnapshot,
        { runtimeObserver.state.value }, foreground::ready,
        { runCatching { android.net.VpnService.prepare(appContext) == null }.getOrDefault(false) }, interactions,
        { repository.ensureSelection() }, io.nekohasekai.libbox.Libbox::checkConfig,
        vpnManager::startForControl, repository::persistSelection, runtimeObserver::pendingRestart,
    )
    val committedConfiguration get() = storage.committedConfiguration
    private val offControl = AndroidOffControl(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, storage::configurationSnapshot,
        { runtimeObserver.state.value }, vpnManager::stopForControl, runtimeObserver::pendingRestart,
    )
    val settingsControl = AndroidSettingsControl(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, commands.scope,
        snapshot = storage::configurationSnapshot,
        commit = { patch, epoch, revision ->
            storage.commitControlSettings(patch, epoch, revision,
                credentialAvailable = { state -> com.kardinal.vpncontrol.data.AndroidHomeSshCredentialStore(appContext)
                    .hasPrivateKey(state.homeSshRouteSettings.credentialVersion) },
                runtimeKnown = runtimeObserver::hasAuthoritativeConfiguration,
            )
        },
        schedule = subscriptionRefreshScheduler::sync,
        pendingRestart = runtimeObserver::pendingRestart,
        busy = { commands.busy.value },
        mutationJobs = commands,
        off = offControl,
        connection = connectionControl,
        updates = { updateActions.control },
        updateInspection = { updateActions.control.inspection { updateState.value } + updateActions.installationInspection() },
        updateInstall = { updateInstall },
        refresh = { subscriptionRefresh },
        benchmark = { locationBenchmark },
        findBest = { findBestControl },
        importKey = { content, epoch, revision -> storage.commitControlSshKey(content, epoch, revision,
            runtimeKnown = runtimeObserver::hasAuthoritativeConfiguration) },
        subscription = storage::commitControlSubscription,
        location = { operation, arguments, epoch, revision -> storage.commitControlLocation(operation, arguments, epoch, revision) { state, raw ->
            orchestrator.selectionFromRawLink(state, raw, "Selected location manually").getOrElse { error("INVALID_ARGUMENT") }
                .also { selected -> runCatching { io.nekohasekai.libbox.Libbox.checkConfig(selected.runtimeConfigJson) }.getOrElse { error("INVALID_ARGUMENT") } }
        } },
        locationRemoval = AndroidLocationDestructiveControl(com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id,
            storage::configurationSnapshot, { runtimeObserver.state.value }, runtimeObserver::captureRuntime,
            vpnManager::stopPinnedForControl,
            { plan, epoch, revision, expected -> storage.commitControlLocationRemoval(plan, epoch, revision) { runtimeObserver.state.value == expected } },
            { point, stopped -> vpnManager.restoreForControl(point, stopped) {
                foreground.ready() && (point.configuration.mode != com.kardinal.vpncontrol.model.AppMode.VPN ||
                    runCatching { android.net.VpnService.prepare(appContext) == null }.getOrDefault(false))
            } }, runtimeObserver::pendingRestart),
        routing = { operation, arguments, epoch, revision -> storage.commitControlRouting(operation, arguments, epoch, revision,
            runtimeObserver::hasAuthoritativeConfiguration, installedAppsCatalog::load) },
        routingImport = { rules, epoch, revision -> storage.commitPreparedControlRouting(rules, epoch, revision,
            runtimeObserver::hasAuthoritativeConfiguration) },
        routingDispatcher = kotlinx.coroutines.Dispatchers.IO,
        retainedResults = AndroidRetainedControlResults { AndroidControlTransferSpool.create(appContext.cacheDir.toPath()) },
        setSource = { arguments, epoch, revision -> storage.commitControlSource(arguments, epoch, revision) {
            when (runtimeObserver.state.value.knowledge) {
                AndroidRuntimeKnowledge.STOPPED -> false
                AndroidRuntimeKnowledge.RUNNING -> if (runtimeObserver.hasAuthoritativeConfiguration()) true else null
                AndroidRuntimeKnowledge.UNKNOWN -> null
            }
        } },
    )
    private val locationBenchmark by lazy { AndroidLocationBenchmarkControl(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, storage::configurationSnapshot,
        orchestrator::stageLocationBenchmark, storage::commitControlBenchmark, runtimeObserver::pendingRestart,
    ) }

    private val findBestControl by lazy { AndroidFindBestControl(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, storage::configurationSnapshot,
        runtimeObserver::pendingRestart, connectionControl::prepareFindBest,
        { state -> AndroidFindBestRuntime.open(runtimeObserver, vpnManager, retainedRuntimeServices) {
            foreground.ready() && (state.appMode != com.kardinal.vpncontrol.model.AppMode.VPN ||
                android.net.VpnService.prepare(appContext) == null)
        } }, orchestrator::stageBestProfileAttemptPlan, orchestrator::verifySelectionCandidate,
        orchestrator::verifyActiveSelection,
        storage::commitControlBestSelection, connectionControl::cancelConsentWait,
        connectionControl::finishFindBestInteraction,
        { failure -> com.kardinal.vpncontrol.data.DiagnosticsLogger.append(appContext,
            AndroidFailureTrace.format("find-best", failure)) },
    ) }

    fun findBestFromGui() { commands.launch {
        val captured = storage.configurationSnapshot()
        val result = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
            com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.FIND_BEST),
            controllerId = captured.controllerId, ifRevision = captured.revision))
        storage.updateStatus(if (result.code == com.kardinal.vpncontrol.model.ControlCode.CANCELLED)
            com.kardinal.vpncontrol.model.BenchmarkStatusMessages.locationSearchCancelled()
            else if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK)
                com.kardinal.vpncontrol.model.BenchmarkStatusMessages.locationSearchFailed()
            else com.kardinal.vpncontrol.ConnectionOrchestrationLogic.refreshSelectionStartedMessage(
                captured.value.appMode, storage.configurationSnapshot().value.selectedProfileName))
    } }

    fun benchmarkLocation(target: AndroidRenderedLocationTarget) {
        commands.launch {
            val captured = storage.configurationSnapshot()
            val ui = MainUiStateProjector.mergePersistedState(MainUiState(), captured.value)
            val current = androidRenderedLocationTarget(ui, target.raw)
            if (target.raw !in captured.value.currentLocations || current.scope != target.scope || current.sourceKey != target.sourceKey) {
                storage.updateStatus(com.kardinal.vpncontrol.model.LocationStatusMessages.locationCheckFailed())
                return@launch
            }
            val result = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(
                java.util.UUID.randomUUID().toString(), com.kardinal.vpncontrol.model.ControlCommand(
                    com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_BENCHMARK,
                    mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(
                        com.kardinal.vpncontrol.data.AndroidLocationControl.identity(captured.controllerId, captured.value, target.raw)))),
                controllerId = captured.controllerId, ifRevision = captured.revision))
            if (!result.ok) storage.updateStatus(if (result.code == com.kardinal.vpncontrol.model.ControlCode.CANCELLED)
                LocationStatusLogic.locationCheckCancelled() else com.kardinal.vpncontrol.model.LocationStatusMessages.locationCheckFailed())
        }
    }

    suspend fun importSshKey(content: String): com.kardinal.vpncontrol.model.ControlResult {
        val committed = storage.configurationSnapshot()
        return settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(
            java.util.UUID.randomUUID().toString(), com.kardinal.vpncontrol.model.ControlCommand(
                com.kardinal.vpncontrol.model.ControlOperationId.SSH_KEY_IMPORT,
                mapOf("input" to com.kardinal.vpncontrol.model.ControlValue.Text(content))),
            controllerId = committed.controllerId, ifRevision = committed.revision))
    }
    suspend fun pendingRestartAfterSettingsSave(): Boolean? =
        runtimeObserver.pendingRestart(storage.configurationSnapshot().value)

    private fun authoritativeRuntimeRunning(): Boolean? = when (runtimeObserver.state.value.knowledge) {
        AndroidRuntimeKnowledge.STOPPED -> false
        AndroidRuntimeKnowledge.RUNNING -> if (runtimeObserver.hasAuthoritativeConfiguration()) true else null
        AndroidRuntimeKnowledge.UNKNOWN -> null
    }

    val controlReader = AndroidControlReader(
        com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id, repository::snapshot,
        runtimeObservation = { runtimeObserver.state.value },
        committedSnapshot = storage::configurationSnapshot,
        pendingRestart = runtimeObserver::pendingRestart,
        settingsWrite = settingsControl::execute,
        routingAdmission = settingsControl::admitRoutingImport,
        routingDocumentAdmission = settingsControl::admitRoutingDocument,
        inputSpool = { AndroidControlInputSpool(AndroidControlTransferSpool.create(appContext.cacheDir.toPath())) },
        operationIdForRequest = settingsControl::operationIdForRequest,
        statusSnapshot = runtimeObserver::controlStatus,
        credentialPresent = { state -> com.kardinal.vpncontrol.data.AndroidHomeSshCredentialStore(appContext)
            .hasPrivateKey(state.homeSshRouteSettings.credentialVersion) },
        updateSnapshot = { updateState.value },
        updateInspection = { updateActions.control.inspection { updateState.value } + updateActions.installationInspection() },
        installedApps = installedAppsCatalog::load,
        diagnosticsExport = diagnosticsExporter::exportText,
    )
    init { storage.observeConnectionLogs(controlReader::observeLogs) }
    private val mutableUpdateState = MutableStateFlow(AppUpdateState())
    val updateState = mutableUpdateState.asStateFlow()
    val updateActions = AndroidUpdateActionsService(
        context = appContext,
        stateProvider = { MainUiState(appUpdate = mutableUpdateState.value) },
        updateState = { transform ->
            mutableUpdateState.value = transform(MainUiState(appUpdate = mutableUpdateState.value)).appUpdate
        },
        launch = commands::launch,
    )

    fun checkAndDownloadUpdate() {
        commands.launch {
            updateActions.showDialog()
            val checked = updateCommand(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_CHECK)
            if (checked.code == com.kardinal.vpncontrol.model.ControlCode.OK && updateActions.control.checkedStatus()?.asset != null)
                updateCommand(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DOWNLOAD)
        }
    }

    fun dismissOrCancelUpdate() { commands.launch { updateCommand(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_DISMISS) } }

    val updateInstall by lazy { AndroidUpdateInstallControl(updateActions.control, interactions,
        recover = updateActions::recoverInstallation, pin = updateActions::pinInstallation) }

    fun installUpdate(launch: (android.content.Intent) -> Unit) {
        commands.launch {
            val committed = storage.configurationSnapshot()
            val result = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
                com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.UPDATES_INSTALL),
                controllerId = committed.controllerId, ifRevision = committed.revision, interactive = true))
            if (result.final) { updateActions.showInstallResult(result); return@launch }
            val operation = result.operationId ?: return@launch
            while (!result.final && interactions.tokenFor(operation) == null) {
                val status = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
                    com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS,
                        mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(operation))), controllerId = committed.controllerId))
                if (status.final) { updateActions.showInstallResult(status); return@launch }
                kotlinx.coroutines.delay(25)
            }
            interactions.tokenFor(operation)?.let { token ->
                runCatching { launch(android.content.Intent(appContext, AndroidControlInteractionActivity::class.java)
                    .putExtra("token", token).putExtra("controllerId", committed.controllerId)) }
                    .onFailure { updateInstall.cancel(operation) }
            }
            while (true) {
                val status = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
                    com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_STATUS,
                        mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(operation))), controllerId = committed.controllerId))
                if (status.final) { updateActions.showInstallResult(status); break }
                kotlinx.coroutines.delay(100)
            }
        }
    }

    val subscriptionRefresh by lazy { AndroidSubscriptionRefreshControl(com.kardinal.vpncontrol.data.AndroidConfigurationEpoch.id,
        storage::configurationSnapshot, { _, _ -> error("CAPTURED_FETCH_REQUIRED") },
        { loads, epoch, revision -> storage.commitControlRefresh(loads, epoch, revision) { runtimeObserver.state.value.knowledge } },
        runtimeObserver::pendingRestart, { state, scheduled ->
            if (scheduled) subscriptionRefreshScheduler.scheduleNext(state) else subscriptionRefreshScheduler.sync(state)
        }, runtimeObserver::captureRuntime, AndroidRefreshSourceLoader(appContext, storage, runtimeObserver)::prepare) }

    suspend fun refreshSubscriptions(target: String, continuation: AndroidRefreshContinuation? = null): com.kardinal.vpncontrol.model.ControlResult {
        val committed = storage.configurationSnapshot()
        return settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
            com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_REFRESH,
                mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(target))),
            controllerId = committed.controllerId, ifRevision = committed.revision), continuation)
    }

    fun refreshSubscriptionsFromGui(target: String) { commands.launch {
        val result = refreshSubscriptions(target)
        val refreshed = (result.data["refreshedCount"] as? com.kardinal.vpncontrol.model.ControlValue.IntegerValue)?.value?.toInt() ?: 0
        val rows = (result.data["subscriptions"] as? com.kardinal.vpncontrol.model.ControlValue.ArrayValue)?.values.orEmpty()
            .mapNotNull { (it as? com.kardinal.vpncontrol.model.ControlValue.ObjectValue)?.values }
        val subscriptions = storage.snapshot().subscriptions
        val failedNames = rows.filter { it["code"] != com.kardinal.vpncontrol.model.ControlValue.Text(com.kardinal.vpncontrol.model.ControlCode.OK.wireName) }
            .mapNotNull { row -> subscriptions.firstOrNull { row["id"] == com.kardinal.vpncontrol.model.ControlValue.Text(it.id) } }
            .map { SubscriptionSourceLogic.sourceLabelFor(subscriptions, it.url) }
        val summary = if (result.data["committed"] == com.kardinal.vpncontrol.model.ControlValue.BooleanValue(true))
            SubscriptionRefreshResultLogic.genericSummary(refreshed, failedNames, rows.size) else result.code.wireName
        repository.updateStatus(summary + if (result.warnings.isNotEmpty()) "\n" + result.warnings.joinToString(", ") else "")
    } }

    fun cancelActiveOperationFromGui() { commands.launch {
        val target = settingsControl.activeFindBestOperationId() ?: settingsControl.activeRefreshOperationId() ?: settingsControl.activeBenchmarkOperationId()
        if (target == null) { commands.cancelActive(); return@launch }
        val committed = storage.configurationSnapshot()
        val result = settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
            com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.OPERATIONS_CANCEL,
                mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(target))),
            controllerId = committed.controllerId, ifRevision = committed.revision))
        if (result.code != com.kardinal.vpncontrol.model.ControlCode.OK) repository.updateStatus(result.code.wireName)
    } }

    private suspend fun updateCommand(operation: com.kardinal.vpncontrol.model.ControlOperationId): com.kardinal.vpncontrol.model.ControlResult {
        val committed = storage.configurationSnapshot()
        return settingsControl.execute(com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
            com.kardinal.vpncontrol.model.ControlCommand(operation), controllerId = committed.controllerId, ifRevision = committed.revision))
    }

    init {
        commands.launch { repository.syncSubscriptionRefreshScheduling() }
    }

    companion object {
        fun get(context: Context): AndroidApplicationOwner =
            (context.applicationContext as VpnControlApplication).controlOwner
    }
}
