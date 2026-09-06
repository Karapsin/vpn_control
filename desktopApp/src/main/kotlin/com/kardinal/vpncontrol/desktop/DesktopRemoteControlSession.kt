package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlProtocolException
import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.control.ControlSnapshotCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Client graph only: cannot construct an owner, touch its workspace, or stop its runtime. */
internal class DesktopRemoteControlSession private constructor(
    initial: ControlSnapshot,
    parentScope: CoroutineScope,
    private val request: suspend (DesktopCliCommand) -> DesktopCliResponse,
    pollMillis: Long,
    private val pollPresentation: Boolean,
) : ControlSession, AutoCloseable {
    private val epoch = initial.controllerId
    private val scope = CoroutineScope(parentScope.coroutineContext + SupervisorJob(parentScope.coroutineContext[Job]))
    private val closed = AtomicBoolean()
    private val refreshMutex = Mutex()
    private val mutableSnapshots = MutableStateFlow(initial)
    override val snapshots = mutableSnapshots.asStateFlow()
    private val mutableFailure = MutableStateFlow<ControlCode?>(null)
    /** A retained snapshot is not proof of live state while this is non-null. */
    val connectionFailure = mutableFailure.asStateFlow()
    private val mutablePresentation = MutableStateFlow<DesktopPresentationSnapshot?>(null)
    val presentations = mutablePresentation.asStateFlow()
    private val mutablePresentationFailure = MutableStateFlow<ControlCode?>(null)
    /** Presentation may be retained for display, but must not be treated as live after failure. */
    val presentationFailure = mutablePresentationFailure.asStateFlow()

    init {
        require(pollMillis > 0)
        scope.launch {
            while (isActive) {
                delay(pollMillis)
                refresh()
                if (pollPresentation) presentation()
            }
        }
    }

    suspend fun refresh(): Result<ControlSnapshot> = refreshMutex.withLock {
        if (closed.get()) return@withLock Result.failure(ControlProtocolException(ControlCode.UNAVAILABLE))
        val result = readSnapshot(request, epoch).mapCatching {
            if (closed.get()) throw ControlProtocolException(ControlCode.UNAVAILABLE)
            if (it.configurationRevision < mutableSnapshots.value.configurationRevision ||
                it.configurationRevision < (mutablePresentation.value?.configurationRevision ?: 0))
                throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
            it
        }
        result.onSuccess { mutableSnapshots.value = it; mutableFailure.value = null }
            .onFailure { mutableFailure.value = (it as? ControlProtocolException)?.code ?: ControlCode.UNAVAILABLE }
        result
    }

    override suspend fun submit(request: ControlRequest): ControlResult {
        if (closed.get()) return failure(request.requestId, ControlCode.UNAVAILABLE)
        if (request.controllerId != null && request.controllerId != epoch) return failure(request.requestId, ControlCode.CONFLICT)
        val bound = request.copy(controllerId = epoch)
        val response = try { this.request(DesktopCliCommand.ControlSubmit(bound)) }
        catch (error: CancellationException) { throw error }
        catch (_: Exception) { return failure(request.requestId, ControlCode.OUTCOME_UNKNOWN) }
        return ControlProtocolCodec.decodeResult(desktopCliJsonResponse(bound, response).message)
    }

    override suspend fun operation(id: String): ControlOperation? =
        refresh().getOrThrow().operations.firstOrNull { it.id == id }

    /** Explicit GUI summary; configuration editors still request their own guarded inputs. */
    suspend fun presentation(): Result<DesktopPresentationSnapshot> = refreshMutex.withLock {
        val captured = readPresentation()
        captured.onSuccess { mutablePresentation.value = it; mutablePresentationFailure.value = null }
            .onFailure { mutablePresentationFailure.value = (it as? ControlProtocolException)?.code ?: ControlCode.UNAVAILABLE }
        captured
    }

    private suspend fun readPresentation(): Result<DesktopPresentationSnapshot> = try {
        if (closed.get()) throw ControlProtocolException(ControlCode.UNAVAILABLE)
        val id = UUID.randomUUID().toString()
        val response = request(DesktopCliCommand.ControlPresentationRead(id, epoch))
        if (!response.success) {
            val code = ControlCode.entries.firstOrNull { it.wireName == response.message && it.exitCode == response.exitCode }
                ?: if (response.isDesktopAppNotRunning) ControlCode.UNAVAILABLE else ControlCode.INCOMPATIBLE_PROTOCOL
            throw ControlProtocolException(code)
        }
        val result = ControlProtocolCodec.decodeResult(response.message)
        if (closed.get()) throw ControlProtocolException(ControlCode.UNAVAILABLE)
        if (result.controllerId != epoch) throw ControlProtocolException(ControlCode.CONFLICT)
        if (result.requestId != id || !result.ok || !result.final ||
            result.code != ControlCode.OK || result.configurationRevision < snapshots.value.configurationRevision ||
            result.configurationRevision < (mutablePresentation.value?.configurationRevision ?: 0))
            throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        val objects = setOf("settings", "runtime", "source", "routing", "activity", "statistics", "update")
        val arrays = setOf("subscriptions", "locations")
        if (result.data.keys != objects + arrays || objects.any { result.data[it] !is ControlValue.ObjectValue } ||
            arrays.any { result.data[it] !is ControlValue.ArrayValue }) throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        if (runCatching { DesktopSourcePresentation.fromValues((result.data.getValue("source") as ControlValue.ObjectValue).values) }.isFailure)
            throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        if (runCatching { DesktopPresentationLocation.fromValues(result.data.getValue("locations")) }.isFailure)
            throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
        val snapshot = DesktopPresentationSnapshot(epoch, result.configurationRevision, result.restartRequired, result.data)
        snapshot.frontend // Reject malformed routine fields before publishing to the frontend.
        Result.success(snapshot)
    } catch (error: CancellationException) { throw error }
    catch (error: ControlProtocolException) { Result.failure(error) }
    catch (_: Exception) { Result.failure(ControlProtocolException(ControlCode.UNAVAILABLE)) }

    override suspend fun cancelOperation(id: String): ControlResult = submit(ControlRequest(
        UUID.randomUUID().toString(), ControlCommand(ControlOperationId.OPERATIONS_CANCEL,
            mapOf("id" to ControlValue.Text(id))), controllerId = epoch))

    private fun failure(id: String, code: ControlCode) =
        ControlProtocolCodec.decodeResult(desktopCliJsonFailure(code, id).message)

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            mutableFailure.value = ControlCode.UNAVAILABLE
            mutablePresentationFailure.value = ControlCode.UNAVAILABLE
            scope.cancel()
        }
    }

    companion object {
        suspend fun connect(
            scope: CoroutineScope,
            request: suspend (DesktopCliCommand) -> DesktopCliResponse = {
                withContext(Dispatchers.IO) { DesktopActivationServer.requestCliCommand(it) }
            },
            pollMillis: Long = 500,
            pollPresentation: Boolean = false,
        ): Result<DesktopRemoteControlSession> = readSnapshot(request, null).map {
            DesktopRemoteControlSession(it, scope, request, pollMillis, pollPresentation)
        }

        private suspend fun readSnapshot(request: suspend (DesktopCliCommand) -> DesktopCliResponse,
            epoch: String?): Result<ControlSnapshot> = try {
            val response = request(DesktopCliCommand.ControlSnapshotRead(epoch))
            if (!response.success) {
                val code = ControlCode.entries.firstOrNull { it.wireName == response.message && it.exitCode == response.exitCode }
                    ?: if (response.isDesktopAppNotRunning) ControlCode.UNAVAILABLE else ControlCode.INCOMPATIBLE_PROTOCOL
                throw ControlProtocolException(code)
            }
            val snapshot = try { ControlSnapshotCodec.decode(response.message) }
            catch (_: ControlProtocolException) { throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL) }
            if (epoch != null && snapshot.controllerId != epoch) throw ControlProtocolException(ControlCode.CONFLICT)
            Result.success(snapshot)
        } catch (error: CancellationException) { throw error }
        catch (error: ControlProtocolException) { Result.failure(error) }
        catch (_: Exception) { Result.failure(ControlProtocolException(ControlCode.UNAVAILABLE)) }
    }
}
