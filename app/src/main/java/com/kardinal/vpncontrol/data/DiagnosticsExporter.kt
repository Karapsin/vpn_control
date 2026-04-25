package com.kardinal.vpncontrol.data

import android.content.ClipData
import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import com.kardinal.vpncontrol.BuildConfig
import java.io.File
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class DiagnosticsExporter(
    private val context: Context,
    private val storage: ProfileStorage,
) {
    suspend fun exportAndShare(): Result<File> = runCatching {
        val exportFile = withContext(Dispatchers.IO) {
            runCatching {
                DiagnosticsLogger.append(context, "Preparing diagnostics export")
                val state = storage.snapshot()
                val exportDir = RuntimeFiles.diagnosticsExportDir(context).apply { mkdirs() }
                val timestamp = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
                .withZone(ZoneId.systemDefault())
                .format(Instant.now())
                val exportFile = File(exportDir, "vpn-control-diagnostics-$timestamp.txt")
                exportFile.writeText(buildDiagnostics(state))
                DiagnosticsLogger.append(context, "Diagnostics bundle written to ${exportFile.name}")
                exportFile
            }.getOrThrow()
        }
        withContext(Dispatchers.Main) {
            share(exportFile)
        }
        DiagnosticsLogger.append(context, "Diagnostics exported to ${exportFile.name}")
        exportFile
    }

    private fun share(file: File) {
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )
        val sendIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "VPN Control diagnostics")
            putExtra(Intent.EXTRA_TEXT, "VPN Control diagnostics export")
            clipData = ClipData.newRawUri(file.name, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(sendIntent, "Export diagnostics").apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(chooser)
    }

    private fun buildDiagnostics(state: com.kardinal.vpncontrol.model.PersistedState): String {
        return buildString {
            appendLine("VPN Control diagnostics")
            appendLine("generated_at=${Instant.now()}")
            appendLine("package=${context.packageName}")
            appendLine("version_name=${BuildConfig.VERSION_NAME}")
            appendLine("version_code=${BuildConfig.VERSION_CODE}")
            appendLine("debug=${BuildConfig.DEBUG}")
            appendLine("android_sdk=${android.os.Build.VERSION.SDK_INT}")
            appendLine("device=${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
            appendLine()
            appendLine("[state]")
            appendLine("profile_url=${RemoteSourceResolver.redactForDiagnostics(state.profileUrl)}")
            appendLine("subscriptions_count=${state.subscriptions.size}")
            appendLine("active_subscription_id=${state.activeSubscriptionId}")
            appendLine("profile_source_mode=${state.profileSourceMode}")
            appendLine("app_mode=${state.appMode}")
            appendLine("subscription_refresh_policy=${state.subscriptionRefreshPolicy}")
            appendLine("find_best_after_subscription_refresh=${state.findBestAfterSubscriptionRefresh}")
            appendLine("subscription_refresh_custom_hours=${state.subscriptionRefreshCustomHours}")
            appendLine("validation_primary_url=${state.validationSettings.primaryUrl}")
            appendLine("validation_secondary_url=${state.validationSettings.secondaryUrl}")
            appendLine("validation_batch_size=${state.validationSettings.batchSize}")
            appendLine("validation_retry_count=${state.validationSettings.retryCount}")
            appendLine("current_locations_count=${state.currentLocations.size}")
            appendLine("custom_dns=${state.customDns}")
            appendLine("use_custom_dns=${state.useCustomDns}")
            appendLine("ignore_rules=${state.routingRules.ignoreRules}")
            appendLine("proxy_packages=${state.routingRules.proxyPackages.joinToString(",")}")
            appendLine("bypass_packages=${state.routingRules.bypassPackages.joinToString(",")}")
            appendLine("national_domain_suffixes=${state.routingRules.nationalDomainSuffixes.joinToString(",")}")
            appendLine("direct_domain_suffixes=${state.routingRules.directDomainSuffixes.joinToString(",")}")
            appendLine("selected_profile_name=${state.selectedProfileName}")
            appendLine("selected_profile_server=${state.selectedProfileServer}")
            appendLine("status_message=${state.statusMessage}")
            appendLine("is_vpn_running=${state.isVpnRunning}")
            appendLine("session_stats_enabled=${state.sessionStatsEnabled}")
            appendLine("live_traffic_stats_enabled=${state.liveTrafficStatsEnabled}")
            appendLine("profile_totals_enabled=${state.profileTotalsEnabled}")
            appendLine("latency_history_enabled=${state.latencyHistoryEnabled}")
            appendLine("connection_log_enabled=${state.connectionLogEnabled}")
            appendLine("connection_test_tools_enabled=${state.connectionTestToolsEnabled}")
            appendLine("session_started_at_epoch_millis=${state.sessionStartedAtEpochMillis}")
            appendLine("session_stopped_at_epoch_millis=${state.sessionStoppedAtEpochMillis}")
            appendLine("session_start_rx_bytes=${state.sessionStartRxBytes}")
            appendLine("session_start_tx_bytes=${state.sessionStartTxBytes}")
            appendLine("successful_starts=${state.successfulStarts}")
            appendLine("successful_stops=${state.successfulStops}")
            appendLine("last_benchmark_summary=${state.lastBenchmarkSummary}")
            appendLine("profile_traffic_totals_count=${state.profileTrafficTotals.size}")
            appendLine("latency_history_count=${state.latencyHistory.size}")
            appendLine("connection_log_count=${state.connectionLog.size}")
            appendLine("proxy_only_port=${SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT}")
            appendLine()
            appendSection(
                "subscriptions",
                state.subscriptions.joinToString(separator = "\n") { subscription ->
                    listOf(
                        "id=${subscription.id}",
                        "name=${subscription.customName.ifBlank { RemoteSourceResolver.preview(subscription.url)?.title ?: "Remote source" }}",
                        "url=${RemoteSourceResolver.redactForDiagnostics(subscription.url)}",
                        "cached=${subscription.cachedLocations.size}",
                        "last_refreshed_at=${subscription.lastRefreshedAtEpochMillis}",
                        "status=${subscription.lastRefreshStatus}",
                    ).joinToString(" | ")
                }.ifBlank { "<empty>" },
            )
            appendSection(
                "selected_profile_link",
                fileOrFallback(
                    file = RuntimeFiles.selectedProfileFile(context),
                    fallback = state.selectedProfileRawLink,
                ),
            )
            appendSection(
                "current_locations",
                state.currentLocations.joinToString(separator = "\n").ifBlank { "<empty>" },
            )
            appendSection(
                "runtime_sing_box_json",
                fileOrFallback(
                    file = RuntimeFiles.runtimeConfigFile(context),
                    fallback = state.runtimeConfigJson,
                ),
            )
            appendSection(
                "profile_traffic_totals",
                state.profileTrafficTotals.joinToString(separator = "\n") { total ->
                    listOf(
                        "name=${total.profileName}",
                        "source=${RemoteSourceResolver.redactForDiagnostics(total.sourceUrl)}",
                        "rx=${total.rxBytes}",
                        "tx=${total.txBytes}",
                        "updated=${total.lastUpdatedAtEpochMillis}",
                    ).joinToString(" | ")
                }.ifBlank { "<empty>" },
            )
            appendSection(
                "latency_history",
                state.latencyHistory.joinToString(separator = "\n") { entry ->
                    listOf(
                        "name=${entry.profileName}",
                        "primary=${entry.primaryStatus}:${entry.primaryTotalMs ?: "n/a"}",
                        "secondary=${entry.secondaryStatus}:${entry.secondaryTotalMs ?: "n/a"}",
                        "created=${entry.createdAtEpochMillis}",
                        "detail=${entry.detail}",
                    ).joinToString(" | ")
                }.ifBlank { "<empty>" },
            )
            appendSection(
                "connection_log",
                state.connectionLog.joinToString(separator = "\n") { entry ->
                    "${entry.createdAtEpochMillis} | ${entry.message}"
                }.ifBlank { "<empty>" },
            )
            appendSection(
                "diagnostics_log",
                safeRead(RuntimeFiles.diagnosticsLogFile(context)),
            )
        }
    }

    private fun safeRead(file: File): String {
        return if (file.exists()) {
            file.readText()
        } else {
            "<missing>"
        }
    }

    private fun fileOrFallback(file: File, fallback: String): String {
        val content = safeRead(file)
        return if (content == "<missing>") fallback else content
    }

    private fun StringBuilder.appendSection(name: String, content: String) {
        appendLine("[$name]")
        appendLine(content.ifBlank { "<empty>" })
        appendLine()
    }
}
