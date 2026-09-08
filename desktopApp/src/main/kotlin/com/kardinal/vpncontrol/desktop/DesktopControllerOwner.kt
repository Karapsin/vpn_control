package com.kardinal.vpncontrol.desktop

import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*

/** Process-owned controller graph. Its lifetime is independent of Compose effects. */
internal class DesktopControllerOwner(
    val service: DesktopAppService,
    val controllerId: String = UUID.randomUUID().toString(),
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) : AutoCloseable, ControlSession {
    init { service.bindRuntimeResourceOwner(controllerId) }

    val session = DesktopHeadlessSession(scope, { service.state }, service::executeCliCommand,
        service::runAutoRefreshCycle, controllerId = controllerId, metadataProvider = service::controlMetadata,
        applySettings = service::applyControlSettingsResponse, inspectSettings = service::controlSettingsSnapshot,
        importSshKey = service::importControlSshKey,
        saveSubscription = service::saveControlSubscriptionResponse,
        saveLocation = service::saveControlLocation,
        mutateLocation = service::mutateControlLocation,
        mutateSource = service::mutateControlSource,
        mutateConfiguration = service::mutateControlConfiguration,
        quitOwner = ::quitForControl,
        install = DesktopControlInstallActions(::installForControl, service::recoverControlInstalls,
            { installHandoff?.retryCancellation() ?: DesktopInstallHandoffResult(ControlCode.NOT_FOUND) },
            settle = { correlation, receipt -> runCatching {
                service.settleControlInstall(correlation, receipt).getOrThrow()
                exitGate.revokeInstallExit(correlation, receipt.jobId)
                synchronized(installExitMonitor) {
                    installExitFrontend?.takeIf { it.correlation == correlation }?.let {
                        installExitFrontend = null
                        it.observer
                    }
                }?.cancel()
                installHandoff?.releaseAfterTerminal(receipt)
            } }),
        inspectStatus = service::controlSnapshot, inspectRead = service::controlReadSnapshot,
        inspectPresentation = service::controlPresentationSnapshot)

    internal val frontends = DesktopOwnerFrontendLifecycle(controllerId, scope,
        initialize = { session.initialize { service.resumePreviousConnectionIfNeeded() } },
        metadata = service::controlMetadata)
    private data class InstallExitFrontend(val correlation: DesktopInstallCorrelation,
        val frontend: DesktopFrontendProcessIdentity?, val observer: kotlinx.coroutines.Job? = null)
    private val installExitMonitor = Any()
    private var installExitFrontend: InstallExitFrontend? = null
    private val exitGate = DesktopOwnerExitGate { correlation, jobId, release ->
        val observer = synchronized(installExitMonitor) {
            val captured = installExitFrontend?.takeIf { it.correlation == correlation }
            if (captured == null) null
            else {
                val frontend = captured.frontend
                if (frontend == null) { release(); null }
                else scope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
                    service.awaitControlInstallFrontendExit(frontend, correlation, jobId)
                    release()
                }.also { installExitFrontend = captured.copy(observer = it) }
            }
        }
        observer?.start()
    }
    private var installHandoff: DesktopInstallHandoff? = null
    private val guiVisibility = DesktopGuiVisibilityControl(controllerId, service::controlMetadata, frontends::registration)
    val exitRequested: Boolean get() = exitGate.exitRequested
    @Volatile var keepAliveRequested: Boolean = false
        private set
    fun requestExitAfterResponse(requestId: String) = exitGate.requestExitAfterResponse(requestId)
    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) = exitGate.responseFlushed(command, response)

    suspend fun execute(command: DesktopCliCommand): DesktopCliResponse =
        when {
            command is DesktopCliCommand.ControlServe -> serveForControl(command)
            command is DesktopCliCommand.ControlFrontendLease -> synchronized(this) {
                if (command.action == DesktopFrontendLeaseAction.ATTACH && session.operationSnapshot().any {
                        it.operation == ControlOperationId.UPDATES_INSTALL && !it.phase.terminal })
                    DesktopCliResponse.failure("BUSY") else frontends.execute(command)
            }
            command is DesktopCliCommand.ControlSubmit && command.request.command.operation in DesktopGuiVisibilityControl.operations ->
                guiVisibility.execute(command.request)
            else -> session.execute(command)
        }

    private fun serveForControl(command: DesktopCliCommand.ControlServe): DesktopCliResponse {
        val code = when {
            !command.valid() -> ControlCode.INVALID_ARGUMENT
            command.controllerId != controllerId -> ControlCode.CONFLICT
            exitGate.exitPending || session.installBarrier() -> ControlCode.BUSY
            else -> {
                keepAliveRequested = true
                frontends.requestResume()
                ControlCode.OK
            }
        }
        val metadata = service.controlMetadata()
        val result = ControlResult(controllerId, command.requestId, code, metadata.configurationRevision,
            restartRequired = metadata.restartRequired,
            data = if (code == ControlCode.OK) mapOf("persistent" to ControlValue.BooleanValue(true)) else emptyMap())
        return DesktopCliResponse(result.ok, ControlDocumentCodec.encodeResult(result), result.exitCode)
    }

    private val mutableSnapshots = MutableStateFlow(captureSnapshot())
    private suspend fun installForControl(correlation: DesktopInstallCorrelation, expectedRevision: Long?): DesktopInstallHandoffResult {
        // No linked-token or inferred Explorer fallback: this adapter is standard-user only.
        val platformFailure = desktopControlInstallPlatform(System.getProperty("os.name")) { runCatching {
            val token = com.sun.jna.platform.win32.WinNT.HANDLEByReference()
            check(com.sun.jna.platform.win32.Advapi32.INSTANCE.OpenProcessToken(
                com.sun.jna.platform.win32.Kernel32.INSTANCE.GetCurrentProcess(), 8, token))
            try {
                val elevation = com.sun.jna.platform.win32.WinNT.TOKEN_ELEVATION()
                check(com.sun.jna.platform.win32.Advapi32.INSTANCE.GetTokenInformation(token.value,
                    20, elevation, elevation.size(), com.sun.jna.ptr.IntByReference()))
                elevation.TokenIsElevated == 0
            } finally { com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(token.value) }
        }.getOrDefault(false) }
        if (platformFailure != null) return DesktopInstallHandoffResult(platformFailure)
        val registration = synchronized(this) { frontends.registration() }
        val frontend = registration?.let { service.controlInstallFrontend(it).getOrElse {
            return DesktopInstallHandoffResult(ControlCode.CONFLICT)
        } }
        synchronized(service) {
            if (expectedRevision != null && expectedRevision != service.configurationRevision)
                return DesktopInstallHandoffResult(ControlCode.CONFLICT)
            if (service.state.isBusy) return DesktopInstallHandoffResult(ControlCode.BUSY)
        }
        val recovery = service.recoverControlInstalls().getOrElse {
            return DesktopInstallHandoffResult(ControlCode.PERSISTENCE_FAILED)
        }
        if (recovery.any { it.blocksInstallation }) return DesktopInstallHandoffResult(ControlCode.BUSY)
        installHandoff?.close()
        val handoff = DesktopInstallHandoff(
            prepare = {
                // Re-read the authenticated fixed endpoint at the actual adapter boundary.
                val refreshed = registration?.let { service.controlInstallFrontend(it).getOrThrow() }
                check(refreshed == frontend) { ControlCode.CONFLICT.name }
                service.prepareControlInstall(correlation, refreshed)
            },
            stopRuntime = service::shutdownForExit, requestExit = {})
        installHandoff = handoff
        val result = handoff.prepare(correlation.requestId)
        if (result.code == ControlCode.OK) {
            synchronized(installExitMonitor) { installExitFrontend = InstallExitFrontend(correlation, frontend) }
            exitGate.requestInstallExitAfterResponse(correlation, requireNotNull(result.jobId))
        }
        return result
    }
    private suspend fun quitForControl(requestId: String, expectedRevision: Long?): DesktopControlWriteResponse {
        synchronized(service) {
            if (expectedRevision != null && expectedRevision != service.configurationRevision)
                return DesktopControlWriteResponse(DesktopCliResponse.failure("CONFLICT"), service.controlMetadata())
            if (service.state.isBusy)
                return DesktopControlWriteResponse(DesktopCliResponse.failure("BUSY"), service.controlMetadata())
        }
        val stopped = service.shutdownForExit()
        if (stopped.isSuccess) requestExitAfterResponse(requestId)
        return DesktopControlWriteResponse(stopped.fold({ DesktopCliResponse.success("") }, {
            DesktopCliResponse.failure(if (it.message == "PERSISTENCE_FAILED") "PERSISTENCE_FAILED" else "RUNTIME_FAILED")
        }), service.controlMetadata())
    }
    override val snapshots = mutableSnapshots.asStateFlow()
    private val snapshotObserver = scope.launch {
        combine(service.controlChanges, session.operationChanges) { _, _ -> Unit }.collect {
            publishSnapshot()
        }
    }

    private fun captureSnapshot(): ControlSnapshot {
        // Capture completed results first: their commit revisions cannot be newer than
        // the following service snapshot. Never nest the service and ledger monitors.
        val operations = session.operationSnapshot()
        return service.controlSnapshot(controllerId).copy(operations = operations)
    }
    @Synchronized private fun publishSnapshot() { mutableSnapshots.value = captureSnapshot() }

    override suspend fun submit(request: ControlRequest): ControlResult = try {
        ControlDocumentCodec.decodeResult(execute(DesktopCliCommand.ControlSubmit(request)).message)
    } finally { publishSnapshot() }

    override suspend fun operation(id: String): ControlOperation? {
        publishSnapshot()
        return snapshots.value.operations.firstOrNull { it.id == id }
    }

    override suspend fun cancelOperation(id: String): ControlResult = submit(ControlRequest(
        UUID.randomUUID().toString(), ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = controllerId))

    suspend fun resumePreviousConnection() = frontends.resumeOnce()

    private val installCleanup = scope.launch(Dispatchers.IO) {
        while (true) {
            service.reconcileTerminalInstallInputs(controllerId)
            kotlinx.coroutines.delay(10_000)
        }
    }

    override fun close() {
        installCleanup.cancel()
        snapshotObserver.cancel()
        session.close()
        scope.cancel()
    }
}

/** Platform classification only; Unix authority and original-user proof belong to native adapters. */
internal fun desktopControlInstallPlatform(osName: String, windowsStandardUser: () -> Boolean): ControlCode? = when {
    osName.startsWith("Linux", true) -> null
    osName.startsWith("Mac", true) -> null
    osName.startsWith("Windows", true) -> if (windowsStandardUser()) null else ControlCode.INTERACTION_REQUIRED
    else -> ControlCode.UNSUPPORTED
}
