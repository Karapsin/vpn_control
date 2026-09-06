package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.flow.StateFlow
import java.util.UUID

/** A frontend has a transport and validated render frames, never a workspace/runtime service. */
internal class DesktopFrontendClient(
    val session: ControlSession,
    val presentations: StateFlow<DesktopPresentationSnapshot?>,
    val failure: StateFlow<ControlCode?>,
) {
    suspend fun submit(request: ControlRequest): ControlResult {
        failure.value?.let { return ControlResult(session.snapshots.value.controllerId, request.requestId, it,
            session.snapshots.value.configurationRevision, final = false) }
        return session.submit(request)
    }
    suspend fun read(operation: ControlOperationId, arguments: Map<String, ControlValue> = emptyMap()) =
        submit(ControlRequest(UUID.randomUUID().toString(), ControlCommand(operation, arguments),
            controllerId = session.snapshots.value.controllerId))

    suspend fun execute(command: DesktopCliCommand): DesktopCliResponse {
        val operation: ControlOperationId
        val args: Map<String, ControlValue>
        when (command) {
            DesktopCliCommand.On -> { operation = ControlOperationId.ON; args = emptyMap() }
            DesktopCliCommand.Off -> { operation = ControlOperationId.OFF; args = emptyMap() }
            DesktopCliCommand.Restart -> { operation = ControlOperationId.RESTART; args = emptyMap() }
            DesktopCliCommand.FindBest -> { operation = ControlOperationId.FIND_BEST; args = emptyMap() }
            is DesktopCliCommand.SubscriptionRefresh -> { operation = ControlOperationId.SUBSCRIPTIONS_REFRESH; args = mapOf("id" to ControlValue.Text(command.target)) }
            is DesktopCliCommand.LocationBenchmark -> { operation = ControlOperationId.LOCATIONS_BENCHMARK; args = mapOf("id" to ControlValue.Text(command.configurationId.orEmpty())) }
            else -> return DesktopCliResponse.failure("UNSUPPORTED")
        }
        val result = read(operation, args)
        return DesktopCliResponse(result.ok, ControlProtocolCodec.encodeResult(result), result.exitCode)
    }
}

internal fun DesktopPresentationMessage.encoded(): String = StatusMessages.encode(key, *args.toTypedArray())

/** Compatibility projection for shared render-only screen arguments; never persisted or submitted. */
internal fun DesktopPresentationSnapshot.toFrontendUiState(): MainUiState {
    val frame = frontend
    val source = (values.getValue("source") as ControlValue.ObjectValue).values
    val sourceMode = (source.getValue("mode") as ControlValue.Text).value
    return MainUiState(
        appLanguage = AppLanguage.entries.single { (if (it == AppLanguage.SYSTEM) "system" else it.code) == frame.settings.language },
        appMode = frame.runtime.configuredMode,
        profileSourceMode = if (sourceMode == "current-locations") ProfileSourceMode.CURRENT_LOCATIONS else ProfileSourceMode.SUBSCRIPTION,
        activeSubscriptionId = (source["subscriptionId"] as? ControlValue.Text)?.value.orEmpty(),
        isVpnRunning = frame.runtime.runtimeRunning, isBusy = frame.activity.busy,
        isRefreshing = frame.activity.refreshing, isStartingVpn = frame.activity.starting,
        selectedProfileName = frame.activity.selectedName,
        statusMessage = frame.activity.status?.encoded().orEmpty(),
        lastBenchmarkSummary = frame.activity.benchmarkSummary?.encoded().orEmpty(),
        startOnBootEnabled = frame.settings.autostart,
        dnsSettings = DnsSettings(mode = when (frame.settings.dnsMode) {
            "custom-doh" -> DnsMode.CUSTOM_DOH; "custom-dot" -> DnsMode.CUSTOM_DOT; else -> DnsMode.AUTOMATIC }),
        homeSshRouteSettings = HomeSshRouteSettings(enabled = frame.settings.sshEnabled,
            port = frame.settings.sshPort.toInt(), relayPort = frame.settings.sshRelayPort.toInt()),
        subscriptionRefreshPolicy = when (frame.settings.refreshPolicy) {
            "every-hour" -> SubscriptionRefreshPolicy.EVERY_HOUR; "custom" -> SubscriptionRefreshPolicy.CUSTOM; else -> SubscriptionRefreshPolicy.OFF },
        subscriptionRefreshCustomHours = frame.settings.refreshCustomHours,
        findBestAfterSubscriptionRefresh = frame.settings.findBestAfterRefresh,
        validationSettings = BenchmarkValidationSettings(batchSize = frame.settings.validationBatchSize.toInt(),
            subscriptionRefreshConcurrency = frame.settings.subscriptionRefreshConcurrency.toInt(),
            retryCount = frame.settings.validationRetryCount.toInt(), activeVerificationWindowSize = frame.settings.validationWindowSize.toInt()),
        routingRules = RoutingRules(ignoreRules = frame.routing.ignoreRules, blockQuicUdp443 = frame.routing.blockQuicUdp443),
        routingIgnoreRulesDraft = frame.routing.ignoreRules,
        sessionStartedAtEpochMillis = frame.statistics.startedAtEpochMillis ?: 0L,
        sessionStoppedAtEpochMillis = frame.statistics.stoppedAtEpochMillis ?: 0L,
        successfulStarts = frame.statistics.successfulStarts.toInt(), successfulStops = frame.statistics.successfulStops.toInt(),
        appUpdate = AppUpdateState(phase = frame.update.phase, currentVersion = frame.update.currentVersion,
            availableVersion = frame.update.availableVersion, downloadedBytes = frame.update.downloadedBytes,
            totalBytes = frame.update.totalBytes, message = frame.update.message?.encoded().orEmpty(),
            releaseNotesUrl = frame.update.releaseNotesUrl.orEmpty()),
    )
}

internal fun desktopFrontendLogs(result: ControlResult): List<ConnectionLogEntry> {
    require(result.ok)
    return (result.data.getValue("entries") as ControlValue.ArrayValue).values.mapIndexed { index, row ->
        val fields = (row as ControlValue.ObjectValue).values
        val timestamp = (fields.getValue("createdAtEpochMillis") as ControlValue.IntegerValue).value
        ConnectionLogEntry((fields["id"] as? ControlValue.Text)?.value ?: "${result.requestId}-$index",
            (fields.getValue("message") as ControlValue.Text).value, timestamp)
    }
}
