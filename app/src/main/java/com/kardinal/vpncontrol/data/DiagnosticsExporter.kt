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
            appendLine("profile_url=${state.profileUrl}")
            appendLine("custom_dns=${state.customDns}")
            appendLine("use_custom_dns=${state.useCustomDns}")
            appendLine("proxy_packages=${state.routingRules.proxyPackages.joinToString(",")}")
            appendLine("bypass_packages=${state.routingRules.bypassPackages.joinToString(",")}")
            appendLine("national_domain_suffixes=${state.routingRules.nationalDomainSuffixes.joinToString(",")}")
            appendLine("direct_domain_suffixes=${state.routingRules.directDomainSuffixes.joinToString(",")}")
            appendLine("selected_profile_name=${state.selectedProfileName}")
            appendLine("selected_profile_server=${state.selectedProfileServer}")
            appendLine("status_message=${state.statusMessage}")
            appendLine("is_vpn_running=${state.isVpnRunning}")
            appendLine("last_benchmark_summary=${state.lastBenchmarkSummary}")
            appendLine()
            appendSection(
                "selected_profile_link",
                safeRead(RuntimeFiles.selectedProfileFile(context)).ifBlank { state.selectedProfileRawLink },
            )
            appendSection(
                "runtime_sing_box_json",
                safeRead(RuntimeFiles.runtimeConfigFile(context)),
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

    private fun StringBuilder.appendSection(name: String, content: String) {
        appendLine("[$name]")
        appendLine(content.ifBlank { "<empty>" })
        appendLine()
    }
}
