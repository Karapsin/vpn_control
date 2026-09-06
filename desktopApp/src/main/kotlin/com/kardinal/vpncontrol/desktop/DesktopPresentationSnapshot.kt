package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.DiagnosticsSanitizer
import com.kardinal.vpncontrol.model.*

/** Routine GUI data, deliberately separate from explicit configuration show/export. */
internal data class DesktopPresentationSnapshot(
    val controllerId: String,
    val configurationRevision: Long,
    val restartRequired: Boolean,
    val values: Map<String, ControlValue>,
) {
    val frontend: DesktopFrontendPresentation get() = DesktopFrontendPresentation.decode(this)
    val source: DesktopSourcePresentation
        get() = DesktopSourcePresentation.fromValues((values.getValue("source") as ControlValue.ObjectValue).values)
    val locations: List<DesktopPresentationLocation>
        get() = DesktopPresentationLocation.fromValues(values.getValue("locations"))
    override fun toString() = "DesktopPresentationSnapshot(revision=$configurationRevision, data=<redacted>)"
}

/** Called only under the service commit monitor. No frontend draft or native UI is consulted. */
internal fun captureDesktopPresentation(service: DesktopAppService, owner: String): DesktopPresentationSnapshot {
    val state = service.state
    val runtime = service.controlSnapshot(owner)
    fun text(value: String): ControlValue = ControlValue.Text(DiagnosticsSanitizer.redactText(value))
    fun number(value: Int): ControlValue = ControlValue.IntegerValue(value.toLong())
    fun flag(value: Boolean): ControlValue = ControlValue.BooleanValue(value)
    fun status(value: String): ControlValue {
        val structured = StatusMessages.decode(value) ?: return ControlValue.Null
        return ControlValue.ObjectValue(mapOf(
            "key" to ControlValue.Text(structured.key.name),
            // Failure arguments may be arbitrary exception text, not public presentation.
            "args" to ControlValue.ArrayValue(structured.args.map {
                if ("FAILED" in structured.key.name) ControlValue.Text("[redacted]") else text(it)
            }),
        ))
    }
    val settings = service.inspectControlSettings().filterKeys { it in presentationSettings } +
        ("autostart" to flag(state.startOnBootEnabled))
    val locations = service.visibleDesktopLocations().mapIndexed { index, row ->
        val id = service.controlLocationId(row)
        ControlValue.ObjectValue(mapOf(
            "id" to (id?.let(ControlValue::Text) ?: ControlValue.Null),
            "index" to number(index + 1),
            "name" to text(row.name), "server" to text(row.server),
            "details" to ControlValue.Text(row.details.takeIf(::safeLocationDetails).orEmpty()),
            "benchmark" to ControlValue.Text(row.benchmarkDetail.takeIf(::safeBenchmarkLabel).orEmpty()),
            "legacyDetailsUnavailable" to flag(!safeLocationDetails(row.details) || !safeBenchmarkLabel(row.benchmarkDetail)),
            "valid" to flag(row.isValid), "selected" to flag(id != null && id == runtime.selectedLocationId),
            "active" to flag(id != null && id == runtime.activeLocationId),
            "editable" to flag(state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS),
        ))
    }
    val sources = state.subscriptions.map { source -> ControlValue.ObjectValue(mapOf(
        "id" to ControlValue.Text(source.id), "name" to text(source.customName),
        "locationCount" to number(source.cachedLocations.size),
        "refreshStatus" to status(source.lastRefreshStatus),
        "refreshStatusUnavailable" to flag(source.lastRefreshStatus.isNotBlank() && StatusMessages.decode(source.lastRefreshStatus) == null),
        "selected" to flag(source.id == state.activeSubscriptionId),
    )) }
    val update = state.appUpdate
    val values = mapOf(
        "settings" to ControlValue.ObjectValue(settings),
        "runtime" to ControlValue.ObjectValue(runtime.toControlValues()),
        "source" to ControlValue.ObjectValue(ControlReadLogic.read(state, ControlCommand(ControlOperationId.SOURCE_SHOW), 0).getOrThrow() +
            DesktopSourcePresentation.capture(state).values()),
        "subscriptions" to ControlValue.ArrayValue(sources),
        "locations" to ControlValue.ArrayValue(locations),
        "routing" to ControlValue.ObjectValue(mapOf(
            "ignoreRules" to flag(state.routingRules.ignoreRules),
            "blockQuicUdp443" to flag(state.routingRules.blockQuicUdp443),
            "directDomainCount" to number(state.routingRules.directDomainSuffixes.size),
            "ruleSetCount" to number(state.routingRules.ruleSets.size),
        )),
        "activity" to ControlValue.ObjectValue(mapOf(
            "busy" to flag(state.isBusy), "refreshing" to flag(state.isRefreshing),
            "starting" to flag(state.isStartingVpn), "status" to status(state.statusMessage),
            "benchmarkSummary" to status(state.lastBenchmarkSummary),
            "benchmarkSummaryUnavailable" to flag(state.lastBenchmarkSummary.isNotBlank() && StatusMessages.decode(state.lastBenchmarkSummary) == null),
            "selectedName" to text(state.selectedProfileName),
            "runtimeDetails" to service.runtimePresentation().values(),
        )),
        "statistics" to ControlValue.ObjectValue(ControlReadLogic.read(state, ControlCommand(ControlOperationId.STATS), System.currentTimeMillis()).getOrThrow()),
        "update" to ControlValue.ObjectValue(mapOf(
            "phase" to ControlValue.Text(update.phase.name.lowercase()),
            "currentVersion" to text(update.currentVersion), "availableVersion" to text(update.availableVersion),
            "downloadedBytes" to ControlValue.IntegerValue(update.downloadedBytes),
            "totalBytes" to ControlValue.IntegerValue(update.totalBytes),
            "releaseNotesUrl" to (safeDesktopReleaseNotesUrl(update.releaseNotesUrl)?.let(ControlValue::Text) ?: ControlValue.Null),
            "releaseNotesUnavailable" to flag(update.releaseNotesUrl.isNotEmpty() && safeDesktopReleaseNotesUrl(update.releaseNotesUrl) == null),
            "message" to status(update.message),
            "messageUnavailable" to flag(update.message.isNotBlank() && StatusMessages.decode(update.message) == null),
        )),
    )
    return DesktopPresentationSnapshot(owner, runtime.configurationRevision, runtime.restartRequired, values)
}

// Endpoints, credentials, test URLs and rule payloads are fetched only by explicit dialog/tab reads.
private val presentationSettings = setOf("mode", "language", "dns.mode", "ssh.enabled", "ssh.port", "ssh.relay-port",
    "refresh.policy", "refresh.custom-hours", "refresh.find-best-after-refresh", "validation.batch-size",
    "validation.subscription-refresh-concurrency", "validation.retry-count", "validation.active-verification-window-size", "autostart")

// Persisted legacy fields can contain arbitrary parser/probe exceptions. Routine views
// carry only recognized display tokens; explicit configuration inspection remains separate.
private fun safeLocationDetails(value: String): Boolean {
    if (value.isEmpty()) return true
    val tokens = value.split(' ')
    return tokens.first() in setOf("VLESS", "Trojan", "Shadowsocks", "VMess", "SOCKS", "Custom") &&
        tokens.drop(1).all { it in setOf("TLS", "REALITY", "WS", "GRPC", "H2", "HTTP", "HTTPUPGRADE", "QUIC",
            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305") }
}

private fun safeBenchmarkLabel(value: String): Boolean = value.isEmpty() || value in setOf(
    "Imported • not checked yet", "Refreshed • not checked yet") ||
    Regex("(?:(?:test|primary|secondary) (?:ok|failed|fail|error|timeout|manual|skipped)|tcp (?:[0-9]+(?:\\.[0-9]+)?ms|unreachable))(?: • (?:(?:test|primary|secondary) (?:ok|failed|fail|error|timeout|manual|skipped)|tcp (?:[0-9]+(?:\\.[0-9]+)?ms|unreachable)))*")
        .matches(value)
