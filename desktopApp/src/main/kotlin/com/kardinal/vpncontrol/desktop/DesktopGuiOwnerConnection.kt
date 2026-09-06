package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.SharingStarted

/** GUI client lifetime only. No service graph, runtime handle, or workspace contents. */
internal class DesktopGuiOwnerConnection private constructor(
    val session: DesktopRemoteControlSession,
    private val frontendId: String,
    private val scope: CoroutineScope,
    private val request: suspend (DesktopCliCommand) -> DesktopCliResponse,
    heartbeatMillis: Long,
) : AutoCloseable {
    private val epoch = session.snapshots.value.controllerId
    private val closed = AtomicBoolean()
    private val mutableFailure = MutableStateFlow<ControlCode?>(null)
    val failure = combine(mutableFailure, session.connectionFailure, session.presentationFailure) { lease, connection, presentation ->
        lease ?: connection ?: presentation
    }.stateIn(scope, SharingStarted.Eagerly, null)
    private val heartbeat = scope.launch {
        while (isActive && !closed.get()) {
            delay(heartbeatMillis)
            try {
                lease(request, epoch, frontendId, DesktopFrontendLeaseAction.HEARTBEAT)
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                mutableFailure.value = (error as? ControlProtocolException)?.code ?: ControlCode.UNAVAILABLE
                // A stale or lost lease is not permission to register against a replacement owner.
                session.close()
                break
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        heartbeat.cancel()
        session.close()
        // Best effort only: process death or scope cancellation falls back to bounded lease expiry.
        scope.launch {
            runCatching { lease(request, epoch, frontendId, DesktopFrontendLeaseAction.DETACH) }
        }
    }

    companion object {
        suspend fun connect(
            scope: CoroutineScope,
            frontendId: String,
            request: suspend (DesktopCliCommand) -> DesktopCliResponse = {
                withContext(Dispatchers.IO) { DesktopActivationServer.requestCliCommand(it) }
            },
            startOwner: suspend (DesktopCliCommand) -> DesktopCliResponse = {
                withContext(Dispatchers.IO) { DesktopHeadlessController.startForCliCommand(it) }
            },
            heartbeatMillis: Long = 5_000L,
            expectedOwnerId: String? = null,
        ): Result<DesktopGuiOwnerConnection> = try {
            require(heartbeatMillis in 1 until DesktopOwnerFrontendLifecycle.LEASE_MILLIS)
            require(DesktopCliCommand.ControlFrontendLease(UUID.randomUUID().toString(), "validation", frontendId,
                DesktopFrontendLeaseAction.ATTACH).valid())
            val boundedRequest: suspend (DesktopCliCommand) -> DesktopCliResponse = { command ->
                try { withTimeout(10_500) { request(command) } }
                catch (_: TimeoutCancellationException) { throw ControlProtocolException(ControlCode.TIMEOUT) }
            }
            val query = DesktopCliCommand.ControlSnapshotRead(controllerId = expectedOwnerId)
            val first = boundedRequest(query)
            // Authentication, malformed protocol, timeout, etc. must never bootstrap a second owner.
            val response = if (first.isDesktopAppNotRunning && expectedOwnerId == null) {
                try { withTimeout(20_000) { startOwner(query) } }
                catch (_: TimeoutCancellationException) { throw ControlProtocolException(ControlCode.TIMEOUT) }
            } else first
            if (!response.success) throw response.failureException()
            val initial = ControlSnapshotCodec.decode(response.message)
            if (expectedOwnerId != null && initial.controllerId != expectedOwnerId) throw ControlProtocolException(ControlCode.CONFLICT)
            lease(boundedRequest, initial.controllerId, frontendId, DesktopFrontendLeaseAction.ATTACH)
            var session: DesktopRemoteControlSession? = null
            try {
                session = DesktopRemoteControlSession.connect(scope, { command ->
                    // The connection's initial snapshot request is pinned too.
                    boundedRequest(if (command is DesktopCliCommand.ControlSnapshotRead && command.controllerId == null)
                        command.copy(controllerId = initial.controllerId) else command)
                }, pollPresentation = true).getOrThrow()
                if (session.snapshots.value.controllerId != initial.controllerId) throw ControlProtocolException(ControlCode.CONFLICT)
                session.presentation().getOrThrow()
                Result.success(DesktopGuiOwnerConnection(session, frontendId, scope, boundedRequest, heartbeatMillis))
            } catch (error: Exception) {
                session?.close()
                withContext(NonCancellable) { runCatching { lease(boundedRequest, initial.controllerId, frontendId, DesktopFrontendLeaseAction.DETACH) } }
                throw error
            }
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) { Result.failure(if (error is ControlProtocolException) error else ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)) }

        private suspend fun lease(request: suspend (DesktopCliCommand) -> DesktopCliResponse,
            epoch: String, frontendId: String, action: DesktopFrontendLeaseAction) {
            val id = UUID.randomUUID().toString()
            val response = try { withTimeout(3_500) { request(DesktopCliCommand.ControlFrontendLease(id, epoch, frontendId, action)) } }
                catch (_: TimeoutCancellationException) { throw ControlProtocolException(ControlCode.TIMEOUT) }
            val result = try { ControlProtocolCodec.decodeResult(response.message) }
                catch (_: Exception) { throw response.failureException() }
            if (result.controllerId != epoch) throw ControlProtocolException(ControlCode.CONFLICT)
            if (result.requestId != id || result.final != true || result.operationId != null ||
                response.success != result.ok || response.exitCode != result.code.exitCode)
                throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
            if (!result.ok) throw ControlProtocolException(result.code)
            if (result.data.keys != setOf("frontendId", "leaseMillis") ||
                result.data["frontendId"] != ControlValue.Text(frontendId) ||
                result.data["leaseMillis"] != ControlValue.IntegerValue(DesktopOwnerFrontendLifecycle.LEASE_MILLIS))
                throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        }

        private fun DesktopCliResponse.failureException() = ControlProtocolException(
            if (isDesktopAppNotRunning) ControlCode.UNAVAILABLE else
                ControlCode.entries.firstOrNull { it.wireName == message && it.exitCode == exitCode } ?: ControlCode.INCOMPATIBLE_PROTOCOL)
    }
}
