package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import java.util.UUID

internal enum class DesktopFrontendProcessObservation { SAME, GONE, UNKNOWN }

/** Missing process metadata is uncertainty, never authority to release installation. */
internal data class DesktopFrontendProcessInspection(
    val present: Boolean,
    val alive: Boolean,
    val startedAtEpochMillis: Long?,
)

internal fun desktopFrontendProcessObservation(
    identity: DesktopFrontendProcessIdentity,
    inspect: (Long) -> DesktopFrontendProcessInspection = { pid ->
        val process = ProcessHandle.of(pid).orElse(null)
        if (process == null) DesktopFrontendProcessInspection(false, false, null)
        else DesktopFrontendProcessInspection(true, process.isAlive,
            process.info().startInstant().orElse(null)?.toEpochMilli())
    },
): DesktopFrontendProcessObservation =
    runCatching {
        val process = inspect(identity.pid)
        if (!process.present || !process.alive) return@runCatching DesktopFrontendProcessObservation.GONE
        val started = process.startedAtEpochMillis
            ?: return@runCatching DesktopFrontendProcessObservation.UNKNOWN
        if (started == identity.startedAtEpochMillis) DesktopFrontendProcessObservation.SAME
        else DesktopFrontendProcessObservation.GONE
    }.getOrDefault(DesktopFrontendProcessObservation.UNKNOWN)

/** One captured install participant; retries never start an installer or target another frontend. */
internal class DesktopInstallFrontendExit(
    identity: DesktopFrontendProcessIdentity,
    correlation: DesktopInstallCorrelation,
    jobId: String,
    private val request: suspend (DesktopCliCommand.ControlSubmit) -> DesktopCliResponse,
    private val observe: () -> DesktopFrontendProcessObservation = { desktopFrontendProcessObservation(identity) },
    private val pause: suspend () -> Unit = { delay(1_000) },
) {
    private val command = DesktopCliCommand.ControlSubmit(ControlRequest(UUID.randomUUID().toString(),
        ControlCommand(ControlOperationId.QUIT, mapOf(
            "owner" to ControlValue.Text(correlation.controllerId),
            "installOperation" to ControlValue.Text(correlation.operationId),
            "jobId" to ControlValue.Text(jobId),
            "pid" to ControlValue.IntegerValue(identity.pid),
            "startedAtEpochMillis" to ControlValue.IntegerValue(identity.startedAtEpochMillis),
        )), controllerId = identity.registrationId), clientTimeoutSeconds = 3)

    init { require(DesktopInstallJobNames.validJob(jobId)) }

    suspend fun awaitExit() {
        while (true) {
            currentCoroutineContext().ensureActive()
            when (runCatching(observe).getOrDefault(DesktopFrontendProcessObservation.UNKNOWN)) {
                DesktopFrontendProcessObservation.GONE -> return
                DesktopFrontendProcessObservation.UNKNOWN -> Unit
                DesktopFrontendProcessObservation.SAME -> {
                    try {
                        val response = request(command)
                        val result = ControlProtocolCodec.decodeResult(response.message)
                        // An acknowledgement only permits the frontend to begin closing. Its
                        // actual disappearance is required before the controller releases its image.
                        check(response.success && response.exitCode == 0 && result == ControlResult(
                            command.request.controllerId, command.request.requestId, ControlCode.OK, 0,
                            data = command.request.command.arguments))
                    } catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) { /* Keep the same request and physical participant. */ }
                }
            }
            pause()
        }
    }
}
