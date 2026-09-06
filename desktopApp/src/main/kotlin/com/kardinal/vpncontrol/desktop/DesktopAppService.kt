package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.awt.ComposeWindow
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainCommandLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.MainUiStateProjector
import com.kardinal.vpncontrol.control.ControlSettingsLogic
import com.kardinal.vpncontrol.control.ControlSettingsPlan
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.nio.file.Path

class DesktopAppService internal constructor(
    private val desktopStore: DesktopStateStore,
    private val runtimeManager: DesktopProxyRuntimeManager,
    private val validationRuntime: DesktopProxyValidationRuntime,
    private val connectionLifecycle: DesktopConnectionLifecycleService,
    private val subscriptionService: DesktopSubscriptionService,
    private val autostartManager: DesktopAutostartManager,
    private val autoRefreshBestSelectionAction: suspend (DesktopAppService) -> Unit,
    initialWorkspace: DesktopWorkspace,
    private val controlPlatform: ControlPlatform? = currentDesktopControlPlatform(),
    locationBenchmarker: DesktopLocationBenchmarker = { profile, dns, urls, settings ->
        validationRuntime.benchmarkLocation(profile, dns, urls, settings)
    },
) {
    private var visualRuntimeStatusDetails: List<String>? = null
    private val controlLocationIdentity = DesktopControlLocationIdentity()
    @Volatile internal var configurationRevision: Long = 0
        private set
    private var resumeConnectionOnLaunch = initialWorkspace.resumeConnectionOnLaunch ||
        initialWorkspace.persistedState.isVpnRunning
    private var launchResumeAttempted = false
    private val restoredInitialState = restoreDesktopUiState(
        initialWorkspace.persistedState,
        initialWorkspace.locations,
    )
    private val normalizedInitialLocations = syncDesktopLocationsWithSelection(
        restoredInitialState,
        initialWorkspace.locations,
    )

    var desktopLocations by mutableStateOf(normalizedInitialLocations)
        private set

    private val mutableControlChanges = kotlinx.coroutines.flow.MutableStateFlow(0L)
    internal val controlChanges: kotlinx.coroutines.flow.StateFlow<Long> = mutableControlChanges

    private var composeState by mutableStateOf(
        syncDesktopUiStateWithLocations(restoredInitialState, normalizedInitialLocations).copy(
            isVpnRunning = false,
            statusMessage = if (resumeConnectionOnLaunch) {
                ConnectionStatusMessages.previousConnectionRestorePending()
            } else {
                initialWorkspace.persistedState.statusMessage
            },
            startOnBootEnabled = autostartManager.inspectEnabled(),
            connectionLog = restoredInitialState.connectionLog.map { it.copy(id = java.util.UUID.randomUUID().toString()) },
        ),
    )
        private set

    private val logCursorJournal = DesktopLogCursorJournal(composeState.connectionLog).also {
        composeState = composeState.copy(connectionLog = it.entries())
    }

    var state: MainUiState
        get() = composeState
        private set(value) {
            synchronized(this) {
                val log = logCursorJournal.sync(value.connectionLog)
                composeState = if (log == value.connectionLog) value else value.copy(connectionLog = log)
                synchronized(mutableControlChanges) { mutableControlChanges.value++ }
            }
        }

    private var committedConfiguration = com.kardinal.vpncontrol.control.ControlConfigurationIdentity.of(state.toPersistedState(desktopLocations))

    private val shutdownHook = DesktopRuntimeShutdownHook(runtimeManager::stopBlocking)
    private val connectionActions = DesktopConnectionActionsService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        connectionLifecycle = connectionLifecycle,
        getResumeConnectionOnLaunch = { resumeConnectionOnLaunch },
        setResumeConnectionOnLaunch = { resumeConnectionOnLaunch = it },
        getLaunchResumeAttempted = { launchResumeAttempted },
        setLaunchResumeAttempted = { launchResumeAttempted = it },
        commitState = { nextLocations, nextState ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = { transform -> state = transform(state) },
    )
    private val locationService = DesktopLocationService(
        captureRestore = ::captureMutationRestore,
        isActiveLocation = { record -> connectionLifecycle.activeConfiguration?.let {
            it.locationReference == record.rawLink && it.sourceReference == record.sourceUrl
        } == true },
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        currentRuntimeMode = { connectionLifecycle.currentRuntimeMode() },
        stopConnection = { message -> connectionActions.stop(message) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val subscriptionManagementService = DesktopSubscriptionManagementService(
        captureRestore = ::captureMutationRestore,
        activeSource = { connectionLifecycle.activeConfiguration?.sourceReference },
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        validateSubscriptionSource = DesktopSubscriptionSourceValidation::validate,
        stopConnection = { message -> connectionActions.stop(message) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
    )
    private val routingRulesService = DesktopRoutingRulesService(
        stateProvider = { state },
        commitState = { nextState -> commitState(nextState = nextState) },
        updateState = ::updateState,
    )
    private val diagnosticsService = DesktopDiagnosticsService(
        stateProvider = { state },
        desktopStore = desktopStore,
        runtimeManager = runtimeManager,
        updateState = ::updateState,
    )
    private val settingsService = DesktopSettingsService(
        stateProvider = { state },
        autostartManager = autostartManager,
        applySettings = { applyControlSettings(it) },
        commitState = { nextState -> commitState(nextState = nextState) },
        updateState = ::updateState,
        homeSshCredentialStore = DesktopHomeSshCredentialStore(desktopStore.runtimeDirectory().parent),
    )
    private val locationBenchmarkService = DesktopLocationBenchmarkService(
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        benchmarkLocation = locationBenchmarker,
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = { transform -> state = transform(state) },
    )
    private val subscriptionRefreshService = DesktopSubscriptionRefreshService(
        captureRestore = ::captureMutationRestore,
        isActiveLocation = { record -> connectionLifecycle.activeConfiguration?.let {
            it.locationReference == record.rawLink && it.sourceReference == record.sourceUrl
        } == true },
        stateProvider = { state },
        locationsProvider = { desktopLocations },
        subscriptionService = subscriptionService,
        isRuntimeRunning = { connectionLifecycle.isRuntimeRunning() },
        stopConnection = { message -> connectionActions.stop(message) },
        findBestAfterRefresh = { autoRefreshBestSelectionAction(this) },
        commitState = { nextState, nextLocations ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = { transform -> state = transform(state) },
    )
    private val findBestService = DesktopFindBestService(
        stateProvider = { state },
        visibleLocationsProvider = { locationService.visibleLocations() },
        locationsProvider = { desktopLocations },
        refreshSubscriptions = { subscriptions, statusPrefix ->
            subscriptionRefreshService.refresh(
                subscriptionsToRefresh = subscriptions,
                statusPrefix = statusPrefix,
            )
        },
        startConnection = { location, summary, activeVerificationPort ->
            connectionActions.start(
                location = location,
                benchmarkSummary = summary,
                activeVerificationPort = activeVerificationPort,
            )
        },
        verifyCandidate = { candidate, dnsSettings, benchmarkUrls, settings ->
            validationRuntime.benchmarkPreflightCandidate(
                candidate = candidate,
                dnsSettings = dnsSettings,
                benchmarkUrls = benchmarkUrls,
                settings = settings,
            )
        },
        commitState = { nextLocations, nextState ->
            commitState(nextState = nextState, nextLocations = nextLocations)
        },
        updateState = ::updateState,
        evaluateProfiles = { profiles, dnsSettings, benchmarkUrls, settings, onProgress ->
            validationRuntime.evaluateProfiles(
                profiles = profiles,
                dnsSettings = dnsSettings,
                benchmarkUrls = benchmarkUrls,
                settings = settings,
                onProgress = onProgress,
            )
        },
    )
    private val runtimeStatusService = DesktopRuntimeStatusService(
        stateProvider = { state },
        currentMode = runtimeManager::currentMode,
        currentPort = runtimeManager::currentPort,
        lastPreflightReport = runtimeManager::lastPreflightReport,
        desktopVpnCapabilityStatus = runtimeManager::desktopVpnCapabilityStatus,
        currentLogFile = runtimeManager::currentLogFile,
        defaultLogFile = runtimeManager::defaultLogFile,
    )
    private val updateService = DesktopUpdateService(
        stateProvider = { state },
        updateState = ::updateState,
        updateDirectory = desktopStore.updateDirectory(),
        workspaceDirectory = desktopStore.updateDirectory().toAbsolutePath().parent,
    )

    internal fun installShutdownHook(): DesktopAppService {
        runCatching { shutdownHook.install() }
        return this
    }

    internal fun forceRunningStateForTesting(forceRunningState: Boolean) {
        resumeConnectionOnLaunch = forceRunningState
        commitState(
            nextState = state.copy(
                isVpnRunning = forceRunningState,
                hasVpnPermission = true,
            ),
        )
    }

    fun shouldResumeConnectionOnLaunch(): Boolean = connectionActions.shouldResumeConnectionOnLaunch()

    suspend fun resumePreviousConnectionIfNeeded() {
        connectionActions.resumePreviousConnectionIfNeeded()
    }

    suspend fun shutdownForExit(): Result<Unit> = connectionActions.shutdownForExit()

    suspend fun checkAndDownloadUpdate() {
        updateService.checkAndDownload()
    }

    internal suspend fun checkControlUpdate(): Result<DesktopUpdateCheck> = updateService.check()
    internal suspend fun downloadControlUpdate(): Result<Unit> = updateService.downloadChecked()
    internal fun checkedControlUpdate(): DesktopUpdateCheck? = updateService.checkedStatus()
    internal fun dismissControlUpdate(): Result<Unit> = updateService.dismiss()

    fun dismissUpdate() {
        updateService.dismiss()
    }

    fun postStatus(message: String) {
        updateState { it.withStatus(message) }
    }

    suspend fun authorizeUpdateInstaller(): Result<Unit> {
        return updateService.authorizeInstallerAndWaitUntilReady(ProcessHandle.current().pid())
    }

    fun reportUpdateInstallFailure(message: String) {
        updateService.reportInstallFailure(message)
    }

    fun cancelUpdateInstaller() {
        updateService.cancelPreparedInstaller()
    }

    fun currentVersion(): String = DesktopBuildInfo.current().displayVersion

    fun openScreen(screen: AppScreen) {
        updateState { it.copy(currentScreen = screen) }
    }

    fun sourceLabelFor(url: String): String {
        return subscriptionManagementService.sourceLabelFor(url)
    }

    fun runtimeStatusDetails(): List<String> {
        return visualRuntimeStatusDetails ?: runtimeStatusService.details()
    }

    internal fun runtimePresentation(): DesktopRuntimePresentation = runtimeStatusService.presentation()

    internal fun setControlRouting(key: String, value: String): Result<Unit> = routingRulesService.setControlValue(key, value)
    internal fun importControlRouting(raw: String): Result<Unit> = routingRulesService.importRaw(raw)
    internal suspend fun controlDiagnosticsReport(): String = diagnosticsService.report()

    internal suspend fun mutateControlConfiguration(command: DesktopCliCommand,
        expectedRevision: Long?): DesktopControlWriteResponse {
        fun failure(code: String) = DesktopControlWriteResponse(DesktopCliResponse.failure(code), controlMetadata())
        val admissionRevision = synchronized(this) {
            if (expectedRevision != null && expectedRevision != configurationRevision) return failure("CONFLICT")
            if (state.isBusy) return failure("BUSY")
            configurationRevision
        }
        fun validate(): Result<Unit> = synchronized(this) {
            if (configurationRevision != admissionRevision) Result.failure(IllegalStateException("CONFLICT"))
            else Result.success(Unit)
        }
        var committed: DesktopControlMetadata? = null
        var committedValues: Map<String, ControlValue>? = null
        val result = when (command) {
            is DesktopCliCommand.RoutingSet, is DesktopCliCommand.RoutingImport -> synchronized(this) {
                validate().getOrElse { return failure("CONFLICT") }
                val saved = when (command) {
                    is DesktopCliCommand.RoutingSet -> routingRulesService.setControlValue(command.key, command.value)
                    is DesktopCliCommand.RoutingImport -> routingRulesService.importRaw(command.content)
                    else -> error("unreachable")
                }
                if (saved.isSuccess) {
                    committed = controlMetadata()
                    committedValues = DesktopConfigurationResultData.routing(state.routingRules,
                        (command as? DesktopCliCommand.RoutingSet)?.key)
                }
                saved
            }
            is DesktopCliCommand.LocationsImport -> locationService.importRaw(command.content,
                validateAdmission = ::validate,
                guardedCommit = { next, rows -> synchronized(this) {
                    validate().getOrElse { return@synchronized Result.failure(it) }
                    commitState(next, rows).also { if (it.isSuccess) {
                        committed = controlMetadata()
                        committedValues = mapOf("importedLocations" to ControlValue.IntegerValue(state.currentLocations.size.toLong()))
                    } }
                } }, captureRestoreAction = ::captureRuntimeOnlyMutationRestore)
            else -> return synchronized(this) { failure("INVALID_ARGUMENT") }
        }
        return synchronized(this) {
            val response = result.fold({ DesktopCliResponse.success(
                com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(requireNotNull(committedValues))) }, { error ->
                val code = when (error.message) {
                    "READ_ONLY" -> "READ_ONLY_SOURCE"
                    "CONFLICT", "BUSY", "INVALID_ARGUMENT", "PERSISTENCE_FAILED", "ROLLBACK_FAILED" -> error.message!!
                    else -> "RUNTIME_FAILED"
                }
                DesktopCliResponse.failure(code)
            })
            DesktopControlWriteResponse(response, committed ?: controlMetadata())
        }
    }

    fun visibleDesktopLocations(): List<DesktopLocationRecord> {
        return locationService.visibleLocations()
    }

    internal fun controlLocationId(location: DesktopLocationRecord): String? =
        controlLocationIdentity.id(location.sourceUrl, location.rawLink)

    internal fun resolveControlLocation(id: String): Result<DesktopLocationRecord> =
        resolveDesktopConfigurationReference(id, visibleDesktopLocations(), ::controlLocationId)

    @Synchronized internal fun saveControlLocation(command: DesktopCliCommand.LocationSave,
        expectedRevision: Long?): DesktopControlWriteResponse {
        fun failure(code: String) = DesktopControlWriteResponse(DesktopCliResponse.failure(code), controlMetadata())
        if (expectedRevision != null && expectedRevision != configurationRevision) return failure("CONFLICT")
        if (state.isBusy) return failure("BUSY")
        if (state.profileSourceMode != ProfileSourceMode.CURRENT_LOCATIONS) return failure("READ_ONLY_SOURCE")
        if (command.configurationId != null && command.target != null) return failure("INVALID_ARGUMENT")
        val target = if (command.configurationId != null) resolveControlLocation(command.configurationId)
            .getOrElse { return failure("CONFLICT") }
        else if (command.target != null) when (val found = com.kardinal.vpncontrol.control.ControlLocationSelection.resolve(
            command.target, visibleDesktopLocations(), DesktopLocationRecord::name)) {
            is com.kardinal.vpncontrol.control.ControlLocationResolution.Found -> found.location
            is com.kardinal.vpncontrol.control.ControlLocationResolution.Rejected -> return failure(found.code.wireName)
        } else null
        val response = saveLocation(command.content, target?.index, target?.rawLink).fold(
            onSuccess = { saved -> DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
                mapOf("id" to ControlValue.Text(requireNotNull(controlLocationId(saved)))))) },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code -> code in setOf("BUSY", "CONFLICT",
                "PERSISTENCE_FAILED", "ROLLBACK_FAILED") } ?: "INVALID_ARGUMENT") })
        return DesktopControlWriteResponse(response, controlMetadata())
    }

    fun selectedDesktopLocation(): DesktopLocationRecord? {
        return locationService.selectedLocation()
    }

    internal fun activeDesktopLocation(): DesktopLocationRecord? =
        connectionLifecycle.activeLocation.takeIf { state.isVpnRunning }

    internal fun activeDesktopMode(): AppMode? =
        connectionLifecycle.currentRuntimeMode().takeIf { state.isVpnRunning }

    internal fun hasPendingRuntimeChanges(): Boolean = state.isVpnRunning &&
        connectionLifecycle.activeConfiguration?.hasPendingChanges(state) == true

    fun activateSelection(targetId: String): Result<Unit> = subscriptionManagementService.activateSelection(targetId)

    fun setSourceMode(mode: ProfileSourceMode): Result<Unit> = subscriptionManagementService.setSourceMode(mode)

    fun toggleAddSubscriptionEditor() {
        subscriptionManagementService.toggleAddSubscriptionEditor()
    }

    fun setProfileDraft(value: String) {
        subscriptionManagementService.setProfileDraft(value)
    }

    fun setProfileTitleDraft(value: String) {
        subscriptionManagementService.setProfileTitleDraft(value)
    }

    fun clearProfileDraft() {
        subscriptionManagementService.clearProfileDraft()
    }

    fun showSubscriptionRenameDialog(subscriptionId: String) {
        subscriptionManagementService.showSubscriptionRenameDialog(subscriptionId)
    }

    fun closeSubscriptionRenameDialog() {
        subscriptionManagementService.closeSubscriptionRenameDialog()
    }

    fun setSubscriptionRenameDraft(value: String) {
        subscriptionManagementService.setSubscriptionRenameDraft(value)
    }

    fun setSubscriptionRenameUrlDraft(value: String) {
        subscriptionManagementService.setSubscriptionRenameUrlDraft(value)
    }

    fun saveSubscriptionRename() {
        subscriptionManagementService.saveSubscriptionRename()
    }

    fun saveSubscriptionDraft() {
        subscriptionManagementService.saveSubscriptionDraft()
    }

    internal fun saveControlSubscription(source: String?, name: String?, id: String?): Result<String> =
        subscriptionManagementService.saveSubscription(source, name, id)

    @Synchronized internal fun saveControlSubscriptionResponse(source: String?, name: String?, id: String?,
        expectedRevision: Long?): DesktopControlWriteResponse {
        if (expectedRevision != null && expectedRevision != configurationRevision)
            return DesktopControlWriteResponse(DesktopCliResponse.failure("CONFLICT"), controlMetadata())
        val response = saveControlSubscription(source, name, id).fold(
            onSuccess = { saved -> DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
                mapOf("id" to ControlValue.Text(saved)))) },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code -> code in setOf("BUSY", "NOT_FOUND",
                "INVALID_ARGUMENT", "PERSISTENCE_FAILED", "ROLLBACK_FAILED") } ?: "RUNTIME_FAILED") })
        return DesktopControlWriteResponse(response, controlMetadata())
    }

    suspend fun deleteSubscription(subscriptionId: String): Result<Unit> =
        subscriptionManagementService.deleteSubscription(subscriptionId)

    internal suspend fun mutateControlSource(command: com.kardinal.vpncontrol.model.ControlCommand,
        expectedRevision: Long?): DesktopControlWriteResponse {
        fun code(error: Throwable) = error.message?.takeIf { it in setOf("CONFLICT", "BUSY", "NOT_FOUND",
            "INVALID_ARGUMENT", "PERSISTENCE_FAILED", "ROLLBACK_FAILED") } ?: "RUNTIME_FAILED"
        fun response(result: Result<Unit>, id: String, metadata: DesktopControlMetadata = controlMetadata()) =
            DesktopControlWriteResponse(result.fold(onSuccess = {
                DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
                    mapOf("id" to ControlValue.Text(id))))
            }, onFailure = { DesktopCliResponse.failure(code(it)) }), metadata)
        fun admission(): Result<Unit> = when {
            expectedRevision != null && expectedRevision != configurationRevision -> Result.failure(IllegalStateException("CONFLICT"))
            state.isBusy -> Result.failure(IllegalStateException("BUSY"))
            else -> Result.success(Unit)
        }
        if (command.operation == com.kardinal.vpncontrol.model.ControlOperationId.SOURCE_SET) return synchronized(this) {
            admission().getOrElse { return@synchronized response(Result.failure(it), "") }
            // GUI source-mode toggle preserves the remembered subscription, including an empty workspace.
            if (command.arguments.keys == setOf("mode")) {
                val mode = when ((command.arguments["mode"] as? ControlValue.Text)?.value) {
                    "current-locations" -> ProfileSourceMode.CURRENT_LOCATIONS
                    "subscription" -> ProfileSourceMode.SUBSCRIPTION
                    else -> return@synchronized response(Result.failure(IllegalArgumentException("INVALID_ARGUMENT")), "")
                }
                return@synchronized response(subscriptionManagementService.setSourceMode(mode),
                    if (mode == ProfileSourceMode.CURRENT_LOCATIONS) "current-locations" else state.activeSubscriptionId.ifBlank { "subscription" })
            }
            val parsed = DesktopControlMutations.command(command) as? DesktopCliCommand.SourceSet
                ?: return@synchronized response(Result.failure(IllegalArgumentException("INVALID_ARGUMENT")), "")
            response(parsed.subscriptionId?.let(subscriptionManagementService::activateSelection)
                ?: subscriptionManagementService.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS),
                if (parsed.subscriptionId == null) "current-locations" else state.activeSubscriptionId.ifBlank { "subscription" })
        }
        val admitted = synchronized(this) {
            admission().mapCatching {
                require(command.operation == com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_DELETE) { "INVALID_ARGUMENT" }
                val parsed = DesktopControlMutations.command(command) as? DesktopCliCommand.SubscriptionDelete
                    ?: throw IllegalArgumentException("INVALID_ARGUMENT")
                require(state.subscriptions.count { it.id == parsed.id } == 1) { "NOT_FOUND" }
                parsed.id to configurationRevision
            }
        }
        val (id, revision) = admitted.getOrElse { return synchronized(this) { response(Result.failure(it), "") } }
        var committed: DesktopControlMetadata? = null
        val result = subscriptionManagementService.deleteSubscription(id,
            validateAdmission = { synchronized(this) {
                if (configurationRevision == revision) Result.success(Unit) else Result.failure(IllegalStateException("CONFLICT"))
            } },
            guardedCommit = { next, rows -> synchronized(this) {
                if (configurationRevision != revision) Result.failure(IllegalStateException("CONFLICT"))
                else commitState(next, rows).onSuccess { committed = controlMetadata() }
            } }, captureRestoreAction = ::captureRuntimeOnlyMutationRestore)
        return synchronized(this) { response(result, id, committed ?: controlMetadata()) }
    }

    fun setSubscriptionRefreshPolicyDraft(policy: SubscriptionRefreshPolicy) {
        updateState { it.copy(subscriptionRefreshPolicyDraft = policy) }
    }

    fun setFindBestAfterSubscriptionRefreshDraft(enabled: Boolean) {
        updateState { it.copy(findBestAfterSubscriptionRefreshDraft = enabled) }
    }

    fun setSubscriptionRefreshCustomHoursDraft(value: String) {
        updateState {
            it.copy(subscriptionRefreshCustomHoursDraft = MainCommandLogic.sanitizeDecimalInput(value).take(6))
        }
    }

    fun toggleDnsDialog() {
        settingsService.toggleDnsDialog()
    }

    fun setDnsModeDraft(mode: com.kardinal.vpncontrol.model.DnsMode) {
        settingsService.setDnsModeDraft(mode)
    }

    fun setCustomDnsDraft(value: String) {
        settingsService.setCustomDnsDraft(value)
    }

    fun saveDns() {
        settingsService.saveDns()
    }

    fun toggleHomeSshRouteDialog() = settingsService.toggleHomeSshRouteDialog()

    fun setHomeSshEnabledDraft(value: Boolean) = settingsService.updateHomeSshDraft {
        it.copy(homeSshEnabledDraft = value)
    }

    fun setHomeSshHostDraft(value: String) = settingsService.updateHomeSshDraft {
        it.copy(homeSshHostDraft = value.take(255))
    }

    fun setHomeSshPortDraft(value: String) = settingsService.updateHomeSshDraft {
        it.copy(homeSshPortDraft = value.filter(Char::isDigit).take(5))
    }

    fun setHomeSshUserDraft(value: String) = settingsService.updateHomeSshDraft {
        it.copy(homeSshUserDraft = value.take(128))
    }

    fun setHomeSshHostKeysDraft(value: String) = settingsService.updateHomeSshDraft {
        it.copy(homeSshHostKeysDraft = value.take(8192))
    }

    fun setHomeSshRelayPortDraft(value: String) = settingsService.updateHomeSshDraft {
        it.copy(homeSshRelayPortDraft = value.filter(Char::isDigit).take(5))
    }

    @Synchronized fun importHomeSshPrivateKey(content: String) = settingsService.importHomeSshPrivateKey(content)

    /** Check the proposal before any credential IO, and capture its own completion metadata. */
    @Synchronized internal fun importControlSshKey(content: String, expectedRevision: Long?): DesktopControlWriteResponse {
        if (expectedRevision != null && expectedRevision != configurationRevision)
            return DesktopControlWriteResponse(DesktopCliResponse.failure("CONFLICT"), controlMetadata())
        val response = importHomeSshPrivateKey(content).fold(
            onSuccess = { DesktopCliResponse.success("OK") },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("INVALID_ARGUMENT", "UNSUPPORTED", "BUSY", "PERSISTENCE_FAILED", "ROLLBACK_FAILED")
            } ?: "RUNTIME_FAILED") },
        )
        return DesktopControlWriteResponse(response, controlMetadata())
    }

    internal fun hasHomeSshPrivateKey(): Boolean =
        DesktopHomeSshCredentialStore(desktopStore.runtimeDirectory().parent).hasPrivateKey()

    fun saveHomeSshRoute() = settingsService.saveHomeSshRoute()

    fun dismissHomeSshRestartDialog() = settingsService.dismissHomeSshRestartDialog()

    suspend fun restartConnection(): Result<Unit> {
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        if (!state.isVpnRunning) return Result.failure(IllegalStateException("NOT_RUNNING"))
        val location = desktopLocations.firstOrNull { it.matchesSelectedLocation(state) }
            ?: return Result.failure(IllegalStateException("NOT_FOUND"))
        val result = connectionActions.start(location, state.lastBenchmarkSummary)
        if (result.isSuccess) settingsService.markHomeSshRestartApplied()
        return result
    }

    suspend fun restartForHomeSshSettings(): Result<Unit> = restartConnection()

    internal suspend fun startSelectedLocationProxy(): Result<Unit> = connectionActions.startSelectedLocation()

    fun setStartOnBootEnabled(enabled: Boolean) {
        settingsService.setStartOnBootEnabled(enabled)
    }

    fun toggleAppModeDialog() {
        settingsService.toggleAppModeDialog()
    }

    fun toggleRefreshPolicyDialog() {
        settingsService.toggleRefreshPolicyDialog()
    }

    fun toggleValidationSettingsDialog() {
        settingsService.toggleValidationSettingsDialog()
    }

    fun toggleLanguageDialog() {
        settingsService.toggleLanguageDialog()
    }

    fun setAppLanguage(language: AppLanguage) {
        settingsService.setAppLanguage(language)
    }

    fun setSubscriptionHwid(value: String) {
        settingsService.setSubscriptionHwid(value)
    }

    fun setValidationTestUrlDraft(value: String) {
        settingsService.setValidationTestUrlDraft(value)
    }

    fun setValidationBatchSizeDraft(value: String) {
        settingsService.setValidationBatchSizeDraft(value)
    }

    fun setValidationSubscriptionRefreshConcurrencyDraft(value: String) {
        settingsService.setValidationSubscriptionRefreshConcurrencyDraft(value)
    }

    fun setValidationRetryCountDraft(value: String) {
        settingsService.setValidationRetryCountDraft(value)
    }

    fun setValidationActiveVerificationWindowSizeDraft(value: String) {
        settingsService.setValidationActiveVerificationWindowSizeDraft(value)
    }

    fun saveValidationSettings() {
        settingsService.saveValidationSettings()
    }

    fun saveSubscriptionRefreshPolicy() {
        settingsService.saveSubscriptionRefreshPolicy()
    }

    suspend fun setAppMode(mode: AppMode): Result<Unit> = settingsService.setAppMode(mode)

    suspend fun toggleAppMode() {
        settingsService.toggleAppMode()
    }

    suspend fun toggleSelectedLocationProxy() {
        connectionActions.toggleSelectedLocationProxy()
    }

    suspend fun refreshAllSubscriptions() {
        subscriptionRefreshService.refreshAll()
    }

    internal suspend fun refreshControlSubscriptions(target: String): Result<DesktopSubscriptionRefreshPayload> {
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        return when (target) {
            "all" -> subscriptionRefreshService.refreshAll()
            "active" -> subscriptionRefreshService.refreshActive()
            else -> subscriptionRefreshService.refreshSubscription(target)
        }
    }

    suspend fun refreshActiveSubscriptions() {
        subscriptionRefreshService.refreshActive()
    }

    suspend fun refreshSubscription(subscriptionId: String) {
        subscriptionRefreshService.refreshSubscription(subscriptionId)
    }

    suspend fun runAutoRefreshCycle() {
        subscriptionRefreshService.runAutoRefreshCycle()
    }

    fun saveLocation(raw: String, index: Int? = null, expectedRaw: String? = null): Result<DesktopLocationRecord> =
        locationService.saveLocation(raw, index, expectedRaw)

    suspend fun deleteLocation(index: Int): Result<Unit> = locationService.deleteLocation(index)

    /** Native stop/restore suspends outside the monitor; its configuration proposal is checked again at commit. */
    internal suspend fun mutateControlLocation(command: com.kardinal.vpncontrol.model.ControlCommand,
        expectedRevision: Long?): DesktopControlWriteResponse {
        fun failure(code: String) = DesktopControlWriteResponse(DesktopCliResponse.failure(code), controlMetadata())
        fun resolve(): Result<DesktopLocationRecord> {
            if (expectedRevision != null && expectedRevision != configurationRevision) return Result.failure(IllegalStateException("CONFLICT"))
            if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
            if ("id" in command.arguments) {
                val id = (command.arguments["id"] as? ControlValue.Text)?.value
                if (command.arguments.keys != setOf("id") || id.isNullOrBlank()) return Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
                return resolveControlLocation(id)
            }
            val selector = when (val parsed = DesktopControlMutations.command(command)) {
                is DesktopCliCommand.Select -> parsed.target
                is DesktopCliCommand.LocationDelete -> parsed.target
                else -> return Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
            }
            return when (val found = com.kardinal.vpncontrol.control.ControlLocationSelection.resolve(selector,
                visibleDesktopLocations(), DesktopLocationRecord::name)) {
                is com.kardinal.vpncontrol.control.ControlLocationResolution.Found -> Result.success(found.location)
                is com.kardinal.vpncontrol.control.ControlLocationResolution.Rejected -> Result.failure(IllegalArgumentException(found.code.wireName))
            }
        }
        fun code(error: Throwable): String = error.message?.takeIf { it in setOf("CONFLICT", "BUSY", "INVALID_ARGUMENT",
            "NOT_FOUND", "AMBIGUOUS_LOCATION", "PERSISTENCE_FAILED", "ROLLBACK_FAILED", "READ_ONLY_SOURCE") } ?: "RUNTIME_FAILED"
        fun success(id: String) = DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
            mapOf("id" to ControlValue.Text(id))))
        if (command.operation == com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_SELECT) return synchronized(this) {
            val row = resolve().getOrElse { return@synchronized failure(code(it)) }
            val id = requireNotNull(controlLocationId(row))
            val response = locationService.applySelection(row.index).fold(
                onSuccess = { success(id) }, onFailure = { DesktopCliResponse.failure(code(it)) })
            DesktopControlWriteResponse(response, controlMetadata())
        }
        if (command.operation != com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_DELETE)
            return synchronized(this) { failure("INVALID_ARGUMENT") }
        val admission = synchronized(this) { resolve().map { Triple(it, configurationRevision, requireNotNull(controlLocationId(it))) } }
        val (row, revision, id) = admission.getOrElse { return synchronized(this) { failure(code(it)) } }
        if (row.sourceUrl.isNotBlank()) return synchronized(this) { failure("READ_ONLY_SOURCE") }
        var committed: DesktopControlMetadata? = null
        val result = locationService.deleteLocation(row.index, row,
            validateAdmission = { synchronized(this) {
                if (configurationRevision == revision) Result.success(Unit) else Result.failure(IllegalStateException("CONFLICT"))
            } },
            guardedCommit = { next, rows -> synchronized(this) {
                if (configurationRevision != revision) Result.failure(IllegalStateException("CONFLICT"))
                else commitState(next, rows).onSuccess { committed = controlMetadata() }
            } },
            captureRestoreAction = ::captureRuntimeOnlyMutationRestore)
        return synchronized(this) { DesktopControlWriteResponse(result.fold(
            onSuccess = { success(id) }, onFailure = { DesktopCliResponse.failure(code(it)) }),
            committed ?: controlMetadata()) }
    }

    private fun captureRuntimeOnlyMutationRestore(): suspend () -> Result<Unit> {
        val restore = connectionLifecycle.captureRuntimeRestore()
        val previousResume = resumeConnectionOnLaunch
        return suspend {
            val restored = restore()
            synchronized(this) {
                resumeConnectionOnLaunch = previousResume
                val restoredState = state.copy(isBusy = false, isVpnRunning = connectionLifecycle.isRuntimeRunning())
                val persisted = commitState(restoredState)
                if (persisted.isFailure) state = restoredState
                if (restored.isSuccess && persisted.isSuccess) Result.success(Unit)
                else Result.failure(IllegalStateException("ROLLBACK_FAILED"))
            }
        }
    }

    fun applyLocationSelection(index: Int, messagePrefix: String = "Selected"): Result<Unit> {
        return locationService.applySelection(index, messagePrefix).onFailure {
            state = state.withStatus(ConnectionStatusMessages.selectedLocationSaveFailed())
        }
    }

    fun applyCliLocationSelection(target: String): Result<DesktopLocationRecord> {
        return locationService.applyCliSelection(target).onFailure { error ->
            if (error is DesktopPersistenceException) {
                state = state.withStatus(ConnectionStatusMessages.selectedLocationSaveFailed())
            }
        }
    }

    fun setRoutingIgnoreRulesDraft(enabled: Boolean) {
        routingRulesService.setIgnoreRulesDraft(enabled)
    }

    fun setRoutingAppSearch(query: String) {
        routingRulesService.setAppSearch(query)
    }

    fun toggleProxyApp(packageName: String) {
        routingRulesService.toggleProxyApp(packageName)
    }

    fun selectAllProxyApps() {
        routingRulesService.selectAllProxyApps()
    }

    fun clearAllProxyApps() {
        routingRulesService.clearAllProxyApps()
    }

    fun setRoutingDirectDomainsDraft(value: String) {
        routingRulesService.setDirectDomainsDraft(value)
    }

    fun addSampleRuleSet() {
        routingRulesService.addSampleRuleSet()
    }

    fun editRuleSet(id: String) {
        routingRulesService.editRuleSet(id)
    }

    fun deleteRuleSet(id: String) {
        routingRulesService.deleteRuleSet(id)
    }

    fun saveRoutingRules() {
        routingRulesService.saveRoutingRules()
    }

    suspend fun stopDesktopProxy(message: String? = null): Result<Unit> {
        return connectionActions.stop(message)
    }

    suspend fun startDesktopProxy(
        location: DesktopLocationRecord,
        benchmarkSummary: String? = null,
    ): Result<Unit> {
        return connectionActions.start(location, benchmarkSummary)
    }

    suspend fun refreshDesktopSubscriptions(
        subscriptionsToRefresh: List<SubscriptionSource>,
        statusPrefix: String,
        stopVpnIfSelectedRemoved: Boolean = true,
    ): Result<Int> {
        return subscriptionRefreshService.refresh(
            subscriptionsToRefresh = subscriptionsToRefresh,
            statusPrefix = statusPrefix,
            stopVpnIfSelectedRemoved = stopVpnIfSelectedRemoved,
        )
    }

    suspend fun importLocationsRaw(raw: String): Result<Unit> = locationService.importRaw(raw)

    suspend fun importLocationsFromClipboard() {
        locationService.importFromClipboard()
    }

    suspend fun importLocationsFromFile(selection: Result<Path?>) {
        locationService.importFromFile(selection)
    }

    fun exportLocationsToClipboard() {
        locationService.exportToClipboard()
    }

    fun exportLocationsToFile(
        window: ComposeWindow,
        title: String = "Export Locations",
    ) {
        locationService.exportToFile(window, title)
    }

    fun importRoutingRulesRaw(raw: String) {
        routingRulesService.importRaw(raw)
    }

    fun importRoutingRulesFromClipboard() {
        routingRulesService.importFromClipboard()
    }

    fun importRoutingRulesFromFile(
        window: ComposeWindow,
        title: String = "Import Routing Rules",
    ) {
        routingRulesService.importFromFile(window, title)
    }

    fun exportRoutingRulesToClipboard() {
        routingRulesService.exportToClipboard()
    }

    fun exportRoutingRulesToFile(
        window: ComposeWindow,
        title: String = "Export Routing Rules",
    ) {
        routingRulesService.exportToFile(window, title)
    }

    suspend fun exportDiagnostics(selection: Result<Path?>) {
        diagnosticsService.export(selection)
    }

    suspend fun benchmarkLocation(index: Int, expectedLocation: DesktopLocationRecord? = null): Result<com.kardinal.vpncontrol.model.ProfileBenchmark> =
        locationBenchmarkService.benchmark(index, expectedLocation)

    suspend fun findBestLocation(
        refreshSubscriptionsFirst: Boolean = true,
    ): Result<Unit> {
        return findBestService.findBestLocation(refreshSubscriptionsFirst)
    }

    /** Replaces only in-memory presentation data for isolated Compose visual tests. */
    internal fun replaceStateForVisualCapture(
        nextState: MainUiState,
        nextLocations: List<DesktopLocationRecord>,
        runtimeStatusDetails: List<String> = emptyList(),
    ) {
        desktopLocations = nextLocations
        state = nextState
        visualRuntimeStatusDetails = runtimeStatusDetails
    }

    private fun captureMutationRestore(): suspend () -> Result<Unit> {
        val restoreRuntime = connectionLifecycle.captureRuntimeRestore()
        val previousState = state.copy(isBusy = false, isRefreshing = false)
        val previousLocations = desktopLocations
        val previousResume = resumeConnectionOnLaunch
        return {
            val restored = restoreRuntime()
            resumeConnectionOnLaunch = previousResume
            val restoredState = previousState.copy(isVpnRunning = connectionLifecycle.isRuntimeRunning())
            val persisted = commitState(restoredState, previousLocations)
            if (persisted.isFailure) state = restoredState
            if (restored.isSuccess && persisted.isSuccess) Result.success(Unit)
            else Result.failure(IllegalStateException("ROLLBACK_FAILED"))
        }
    }

    @Synchronized private fun commitState(
        nextState: MainUiState,
        nextLocations: List<DesktopLocationRecord> = desktopLocations,
    ): Result<Unit> {
        val syncedState = syncDesktopUiStateWithLocations(nextState, nextLocations)
        val syncedLocations = syncDesktopLocationsWithSelection(syncedState, nextLocations)
        val persisted = syncedState.toPersistedState(syncedLocations)
        val configuration = com.kardinal.vpncontrol.control.ControlConfigurationIdentity.of(persisted)
        val configurationChanged = configuration != committedConfiguration
        if (configurationChanged && configurationRevision == Long.MAX_VALUE)
            return Result.failure(IllegalStateException("CONFLICT"))
        return desktopStore.writeWorkspace(
            DesktopWorkspace(
                persistedState = persisted,
                locations = syncedLocations,
                resumeConnectionOnLaunch = resumeConnectionOnLaunch,
            ),
        ).onSuccess {
            committedConfiguration = configuration
            if (configurationChanged) configurationRevision++
            desktopLocations = syncedLocations
            state = syncedState
        }
    }

    @Synchronized private fun updateState(transform: (MainUiState) -> MainUiState) {
        commitState(transform(state))
    }

    @Synchronized internal fun inspectControlSettings(): Map<String, ControlValue> =
        ControlSettingsLogic.inspect(state.toPersistedState(desktopLocations))

    @Synchronized internal fun controlMetadata(): DesktopControlMetadata =
        DesktopControlMetadata(configurationRevision, hasPendingRuntimeChanges())

    @Synchronized internal fun controlSettingsSnapshot(): DesktopControlSettingsSnapshot =
        DesktopControlSettingsSnapshot(controlMetadata(), inspectControlSettings())

    @Synchronized internal fun controlPresentationSnapshot(controllerId: String): DesktopPresentationSnapshot =
        captureDesktopPresentation(this, controllerId)

    @Synchronized internal fun controlReadSnapshot(command: com.kardinal.vpncontrol.model.ControlCommand): DesktopControlReadSnapshot =
        if (command.operation == com.kardinal.vpncontrol.model.ControlOperationId.LOGS)
            DesktopControlReadSnapshot(controlMetadata(), logCursorJournal.read(command.arguments))
        else DesktopControlInspection.read(this, command, controlMetadata())

    @Synchronized internal fun controlSnapshot(controllerId: String): com.kardinal.vpncontrol.model.ControlSnapshot {
        val captured = connectionLifecycle.activeConnection
        val running = connectionLifecycle.isRuntimeRunning()
        val active = captured.takeIf { running }
        return com.kardinal.vpncontrol.model.ControlSnapshot(
            controllerId = controllerId, configurationRevision = configurationRevision,
            selectedLocationId = controlLocationIdentity.id(state.selectedProfileSourceUrl, state.selectedProfileRawLink),
            activeLocationId = active?.configuration?.let { controlLocationIdentity.id(it.sourceReference, it.locationReference) },
            configuredMode = state.appMode, activeMode = if (running) active?.configuration?.mode
                ?: connectionLifecycle.currentRuntimeMode() else null,
            runtimeId = active?.runtimeId, runtimeStartedAt = active?.startedAt,
            restartRequired = active?.configuration?.hasPendingChanges(state) == true,
            runtimeRunning = running,
        )
    }

    /** The session must validate the controller epoch before supplying a revision. */
    @Synchronized internal fun applyControlSettingsResponse(patch: Map<String, ControlValue>, expectedRevision: Long?): DesktopControlWriteResponse {
        val response = applyControlSettings(patch, expectedRevision).fold(
            onSuccess = { DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(it)) },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("INVALID_ARGUMENT", "UNSUPPORTED", "BUSY", "CONFLICT", "PERSISTENCE_FAILED")
            } ?: "RUNTIME_FAILED") },
        )

        return DesktopControlWriteResponse(response, controlMetadata())
    }

    /** The session must validate the controller epoch before supplying a revision. */
    @Synchronized internal fun applyControlSettings(
        patch: Map<String, ControlValue>,
        expectedRevision: Long? = null,
    ): Result<Map<String, ControlValue>> {
        if (expectedRevision != null && expectedRevision != configurationRevision)
            return Result.failure(IllegalStateException("CONFLICT"))
        if (state.isBusy) return Result.failure(IllegalStateException("BUSY"))
        val platform = controlPlatform ?: return Result.failure(IllegalStateException("UNSUPPORTED"))
        return when (val plan = ControlSettingsLogic.plan(state.toPersistedState(desktopLocations), patch, platform,
            DesktopHomeSshCredentialStore(desktopStore.runtimeDirectory().parent).hasPrivateKey())) {
            is ControlSettingsPlan.Rejected -> Result.failure(IllegalArgumentException(plan.code.wireName))
            is ControlSettingsPlan.Configuration -> commitState(MainUiStateProjector.mergePersistedState(state, plan.state)).map { plan.normalized }
            is ControlSettingsPlan.Autostart -> {
                val previous = autostartManager.inspectEnabled()
                if (previous != plan.enabled && configurationRevision == Long.MAX_VALUE)
                    return Result.failure(IllegalStateException("CONFLICT"))
                val result = autostartManager.setEnabled(plan.enabled)
                val actual = autostartManager.inspectEnabled()
                if (result.isFailure || actual != plan.enabled)
                    return Result.failure(IllegalStateException("PERSISTENCE_FAILED"))
                if (actual != previous) configurationRevision++
                state = state.copy(startOnBootEnabled = actual)
                Result.success(mapOf("autostart" to ControlValue.BooleanValue(actual)))
            }
        }
    }
}
