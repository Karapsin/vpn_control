package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*

/** Validated presentation only: no service, persisted graph, editor payload, or filesystem reference. */
internal data class DesktopFrontendPresentation(
    val settings: DesktopPresentationSettings,
    val runtime: ControlSnapshot,
    val source: DesktopSourcePresentation,
    val locations: List<DesktopPresentationLocation>,
    val subscriptions: List<DesktopPresentationSubscription>,
    val routing: DesktopPresentationRouting,
    val activity: DesktopPresentationActivity,
    val statistics: DesktopPresentationStatistics,
    val update: DesktopPresentationUpdate,
) {
    override fun toString() = "DesktopFrontendPresentation(data=<redacted>)"

    companion object {
        fun decode(snapshot: DesktopPresentationSnapshot): DesktopFrontendPresentation = try {
            val data = snapshot.values
            require(data.keys == setOf("settings", "runtime", "source", "locations", "subscriptions", "routing", "activity", "statistics", "update"))
            fun section(key: String) = (data.getValue(key) as ControlValue.ObjectValue).values
            val settings = section("settings").let { s ->
                s.keysExactly("mode", "language", "dns.mode", "autostart", "ssh.enabled", "ssh.port", "ssh.relay-port", "refresh.policy",
                    "refresh.custom-hours", "refresh.find-best-after-refresh", "validation.batch-size",
                    "validation.subscription-refresh-concurrency", "validation.retry-count", "validation.active-verification-window-size")
                DesktopPresentationSettings(
                    s.text("mode").also { require(it in setOf("vpn", "proxy-only")) },
                    s.text("language").also { require(it in AppLanguage.entries.map { l -> if (l == AppLanguage.SYSTEM) "system" else l.code }) },
                    s.text("dns.mode").also { require(it in setOf("automatic", "custom-doh", "custom-dot")) },
                    s.flag("ssh.enabled"), s.number("ssh.port").also { require(it in 1..65535) },
                    s.number("ssh.relay-port").also { require(it in 1..65535) },
                    s.text("refresh.policy").also { require(it in setOf("off", "every-hour", "custom")) },
                    (s.getValue("refresh.custom-hours") as ControlValue.DecimalValue).value.also { require(it.isFinite() && it > 0) },
                    s.flag("refresh.find-best-after-refresh"), s.number("validation.batch-size"),
                    s.number("validation.subscription-refresh-concurrency"), s.number("validation.retry-count"),
                    s.number("validation.active-verification-window-size"), s.flag("autostart"))
            }
            val runtimeValues = section("runtime")
            runtimeValues.keysExactly("runtimeRunning", "selectedLocationId", "activeLocationId", "configuredMode", "activeMode",
                "runtimeId", "runtimeStartedAt", "restartRequired")
            val runtime = ControlSnapshotCodec.decode(ControlProtocolCodec.encodeValues(runtimeValues + mapOf(
                "schemaVersion" to ControlValue.IntegerValue(CONTROL_SCHEMA_VERSION.toLong()),
                "controllerId" to ControlValue.Text(snapshot.controllerId),
                "configurationRevision" to ControlValue.IntegerValue(snapshot.configurationRevision),
                "operations" to ControlValue.ArrayValue(emptyList()))))
            require(runtime.restartRequired == snapshot.restartRequired)
            require((runtime.configuredMode == AppMode.VPN) == (settings.mode == "vpn"))
            val source = section("source")
            source.keysExactly("mode", "subscriptionId", "selectedSource", "currentSource", "selectedOutsideCurrent")
            require(source.text("mode") in setOf("current-locations", "subscription"))
            require(source.getValue("subscriptionId") == ControlValue.Null || source.getValue("subscriptionId") is ControlValue.Text)
            val subscriptions = (data.getValue("subscriptions") as ControlValue.ArrayValue).values.map { value ->
                val s = (value as ControlValue.ObjectValue).values
                s.keysExactly("id", "name", "locationCount", "selected", "refreshStatus", "refreshStatusUnavailable")
                DesktopPresentationSubscription(s.text("id").also { require(it.isNotBlank()) }, s.text("name"),
                    s.number("locationCount"), s.flag("selected"), s.message("refreshStatus"), s.flag("refreshStatusUnavailable"))
            }
            require(subscriptions.map { it.id }.distinct().size == subscriptions.size)
            val routing = section("routing").let { s ->
                s.keysExactly("ignoreRules", "blockQuicUdp443", "directDomainCount", "ruleSetCount")
                DesktopPresentationRouting(s.flag("ignoreRules"), s.flag("blockQuicUdp443"), s.number("directDomainCount"), s.number("ruleSetCount"))
            }
            val activity = section("activity").let { s ->
                s.keysExactly("busy", "refreshing", "starting", "status", "selectedName", "benchmarkSummary", "benchmarkSummaryUnavailable", "runtimeDetails")
                DesktopPresentationActivity(s.flag("busy"), s.flag("refreshing"), s.flag("starting"), s.message("status"),
                    s.text("selectedName"), s.message("benchmarkSummary"), s.flag("benchmarkSummaryUnavailable"),
                    DesktopRuntimePresentation.decode(s.getValue("runtimeDetails")))
            }
            val statistics = section("statistics").let { s ->
                s.keysExactly("running", "startedAtEpochMillis", "stoppedAtEpochMillis", "elapsedMillis", "successfulStarts", "successfulStops")
                DesktopPresentationStatistics(s.flag("running"), s.optionalNumber("startedAtEpochMillis"),
                    s.optionalNumber("stoppedAtEpochMillis"), s.optionalNumber("elapsedMillis"), s.number("successfulStarts"), s.number("successfulStops"))
            }
            require(statistics.running == runtime.runtimeRunning)
            val update = section("update").let { s ->
                s.keysExactly("phase", "currentVersion", "availableVersion", "downloadedBytes", "totalBytes", "message", "messageUnavailable", "releaseNotesUrl", "releaseNotesUnavailable")
                val notes = if (s.getValue("releaseNotesUrl") == ControlValue.Null) null else s.text("releaseNotesUrl").also {
                    require(safeDesktopReleaseNotesUrl(it) != null)
                }
                DesktopPresentationUpdate(AppUpdatePhase.entries.single { it.name.lowercase() == s.text("phase") },
                    s.text("currentVersion"), s.text("availableVersion"), s.number("downloadedBytes"), s.number("totalBytes"),
                    s.message("message"), s.flag("messageUnavailable"), notes, s.flag("releaseNotesUnavailable"))
            }
            DesktopFrontendPresentation(settings, runtime, DesktopSourcePresentation.fromValues(source), snapshot.locations,
                subscriptions, routing, activity, statistics, update)
        } catch (_: Exception) { throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL) }
    }
}

internal data class DesktopPresentationSettings(val mode: String, val language: String, val dnsMode: String,
    val sshEnabled: Boolean, val sshPort: Long, val sshRelayPort: Long, val refreshPolicy: String,
    val refreshCustomHours: Double, val findBestAfterRefresh: Boolean, val validationBatchSize: Long,
    val subscriptionRefreshConcurrency: Long, val validationRetryCount: Long, val validationWindowSize: Long, val autostart: Boolean)
internal data class DesktopPresentationSubscription(val id: String, val name: String, val locationCount: Long,
    val selected: Boolean, val refreshStatus: DesktopPresentationMessage?, val refreshStatusUnavailable: Boolean)
internal data class DesktopPresentationRouting(val ignoreRules: Boolean, val blockQuicUdp443: Boolean,
    val directDomainCount: Long, val ruleSetCount: Long)
internal data class DesktopPresentationActivity(val busy: Boolean, val refreshing: Boolean, val starting: Boolean,
    val status: DesktopPresentationMessage?, val selectedName: String, val benchmarkSummary: DesktopPresentationMessage?,
    val benchmarkSummaryUnavailable: Boolean, val runtimeDetails: DesktopRuntimePresentation)
internal data class DesktopPresentationStatistics(val running: Boolean, val startedAtEpochMillis: Long?,
    val stoppedAtEpochMillis: Long?, val elapsedMillis: Long?, val successfulStarts: Long, val successfulStops: Long)
internal data class DesktopPresentationUpdate(val phase: AppUpdatePhase, val currentVersion: String,
    val availableVersion: String, val downloadedBytes: Long, val totalBytes: Long,
    val message: DesktopPresentationMessage?, val messageUnavailable: Boolean,
    val releaseNotesUrl: String?, val releaseNotesUnavailable: Boolean)
internal data class DesktopPresentationMessage(val key: StatusMessageKey, val args: List<String>) {
    override fun toString() = "DesktopPresentationMessage(key=$key, args=<redacted>)"
}
private fun Map<String, ControlValue>.keysExactly(vararg keys: String) { require(this.keys == keys.toSet()) }
private fun Map<String, ControlValue>.text(key: String) = (getValue(key) as ControlValue.Text).value
private fun Map<String, ControlValue>.flag(key: String) = (getValue(key) as ControlValue.BooleanValue).value
private fun Map<String, ControlValue>.number(key: String) = (getValue(key) as ControlValue.IntegerValue).value.also { require(it >= 0) }
private fun Map<String, ControlValue>.optionalNumber(key: String) = if (getValue(key) == ControlValue.Null) null else number(key)
private fun Map<String, ControlValue>.message(key: String): DesktopPresentationMessage? {
    if (getValue(key) == ControlValue.Null) return null
    val s = (getValue(key) as ControlValue.ObjectValue).values
    s.keysExactly("key", "args")
    return DesktopPresentationMessage(StatusMessageKey.valueOf(s.text("key")),
        (s.getValue("args") as ControlValue.ArrayValue).values.map { (it as ControlValue.Text).value })
}
