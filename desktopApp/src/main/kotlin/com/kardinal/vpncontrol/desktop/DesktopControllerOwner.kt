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
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*

/** Process-owned controller graph. Its lifetime is independent of Compose effects. */
internal class DesktopControllerOwner(
    val service: DesktopAppService,
    val controllerId: String = UUID.randomUUID().toString(),
    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) : AutoCloseable, ControlSession {
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
        inspectStatus = service::controlSnapshot, inspectRead = service::controlReadSnapshot,
        inspectPresentation = service::controlPresentationSnapshot)

    internal val frontends = DesktopOwnerFrontendLifecycle(controllerId, scope,
        initialize = { session.initialize { service.resumePreviousConnectionIfNeeded() } },
        metadata = service::controlMetadata)
    private val exitGate = DesktopOwnerExitGate()
    private val guiVisibility = DesktopGuiVisibilityControl(controllerId, service::controlMetadata, frontends::registration)
    val exitRequested: Boolean get() = exitGate.exitRequested
    fun requestExitAfterResponse(requestId: String) = exitGate.requestExitAfterResponse(requestId)
    fun responseFlushed(command: DesktopCliCommand, response: DesktopCliResponse) = exitGate.responseFlushed(command, response)

    suspend fun execute(command: DesktopCliCommand): DesktopCliResponse =
        when {
            command is DesktopCliCommand.ControlFrontendLease -> frontends.execute(command)
            command is DesktopCliCommand.ControlSubmit && command.request.command.operation in DesktopGuiVisibilityControl.operations ->
                guiVisibility.execute(command.request)
            else -> session.execute(command)
        }

    private val mutableSnapshots = MutableStateFlow(captureSnapshot())
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
        ControlProtocolCodec.decodeResult(execute(DesktopCliCommand.ControlSubmit(request)).message)
    } finally { publishSnapshot() }

    override suspend fun operation(id: String): ControlOperation? {
        publishSnapshot()
        return snapshots.value.operations.firstOrNull { it.id == id }
    }

    override suspend fun cancelOperation(id: String): ControlResult = submit(ControlRequest(
        UUID.randomUUID().toString(), ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = controllerId))

    suspend fun resumePreviousConnection() = frontends.resumeOnce()

    override fun close() {
        snapshotObserver.cancel()
        session.close()
        scope.cancel()
    }
}
