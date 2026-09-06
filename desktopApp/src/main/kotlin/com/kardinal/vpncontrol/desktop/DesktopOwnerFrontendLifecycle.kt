package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*

internal enum class DesktopFrontendLeaseAction { ATTACH, HEARTBEAT, DETACH }

/** One bounded presentation lease; expiry never performs a runtime action. */
internal class DesktopOwnerFrontendLifecycle(
    private val controllerId: String,
    private val scope: CoroutineScope,
    private val initialize: suspend () -> Unit,
    private val metadata: () -> DesktopControlMetadata,
    private val nowMillis: () -> Long = { System.nanoTime() / 1_000_000 },
    private val leaseMillis: Long = LEASE_MILLIS,
) {
    private var frontend: String? = null
    private var touched = 0L
    private var initialization: Deferred<Unit>? = null
    init { require(leaseMillis > 0) }

    private fun initialization(): Deferred<Unit> {
        val job = synchronized(this) {
            initialization ?: scope.async(start = CoroutineStart.LAZY) { initialize() }.also { initialization = it }
        }
        job.start() // No native initialization while holding the lease monitor.
        return job
    }
    suspend fun resumeOnce() { initialization().await() }
    @Synchronized fun hasOwnedWork(): Boolean {
        expire()
        return frontend != null || initialization?.isCompleted == false
    }
    @Synchronized fun registration(): String? { expire(); return frontend }
    private fun expire() {
        if (frontend != null && nowMillis() - touched >= leaseMillis) frontend = null
    }
    fun execute(command: DesktopCliCommand.ControlFrontendLease): DesktopCliResponse {
        val code = when {
            !command.valid() -> ControlCode.INVALID_ARGUMENT
            command.controllerId != controllerId -> ControlCode.CONFLICT
            else -> synchronized(this) {
                expire()
                when (command.action) {
                    DesktopFrontendLeaseAction.ATTACH -> if (frontend != null && frontend != command.frontendId) ControlCode.BUSY else {
                        frontend = command.frontendId; touched = nowMillis(); ControlCode.OK
                    }
                    DesktopFrontendLeaseAction.HEARTBEAT -> if (frontend != command.frontendId) ControlCode.NOT_FOUND else {
                        touched = nowMillis(); ControlCode.OK
                    }
                    DesktopFrontendLeaseAction.DETACH -> if (frontend != null && frontend != command.frontendId) ControlCode.CONFLICT else {
                        frontend = null; ControlCode.OK
                    }
                }
            }
        }
        if (code == ControlCode.OK && command.action == DesktopFrontendLeaseAction.ATTACH) initialization()
        val current = metadata()
        val result = ControlResult(controllerId, command.requestId, code, current.configurationRevision,
            restartRequired = current.restartRequired, data = if (code == ControlCode.OK) mapOf(
                "frontendId" to ControlValue.Text(command.frontendId),
                "leaseMillis" to ControlValue.IntegerValue(leaseMillis),
            ) else emptyMap())
        return DesktopCliResponse(code == ControlCode.OK, ControlProtocolCodec.encodeResult(result), code.exitCode)
    }
    companion object { const val LEASE_MILLIS = 15_000L }
}

internal fun DesktopCliCommand.ControlFrontendLease.valid(): Boolean =
    controllerId.isNotBlank() && controllerId.length <= 128 &&
        canonicalFrontendUuid(requestId) && canonicalFrontendUuid(frontendId)
private fun canonicalFrontendUuid(value: String): Boolean =
    Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").matches(value)
