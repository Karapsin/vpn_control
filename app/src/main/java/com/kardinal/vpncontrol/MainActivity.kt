package com.kardinal.vpncontrol

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.kardinal.vpncontrol.ui.VpnControlApp

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        MainViewModel.factory(applicationContext)
    }
    private var pendingRoutingRulesExport: String? = null
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) {
        if (VpnService.prepare(this) == null) {
            viewModel.onVpnPermissionGranted()
            viewModel.toggleVpn()
        }
    }
    private val exportRoutingRulesLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri ->
        val content = pendingRoutingRulesExport
        pendingRoutingRulesExport = null
        if (uri == null || content == null) {
            viewModel.postStatus("Routing rules export canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { writer ->
                writer.write(content)
            } ?: error("Could not open export destination")
        }.onSuccess {
            viewModel.postStatus("Routing rules exported")
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to export routing rules")
        }
    }
    private val importRoutingRulesLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri == null) {
            viewModel.postStatus("Routing rules import canceled")
            return@registerForActivityResult
        }

        runCatching {
            contentResolver.openInputStream(uri)?.bufferedReader()?.use { reader ->
                reader.readText()
            } ?: error("Could not open selected rules file")
        }.onSuccess { raw ->
            viewModel.importRoutingRules(raw)
        }.onFailure { error ->
            viewModel.postStatus(error.message ?: "Failed to import routing rules")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            val state = viewModel.uiState.collectAsStateWithLifecycle()
            VpnControlApp(
                state = state.value,
                onToggleProfileDialog = viewModel::toggleProfileDialog,
                onProfileChange = viewModel::onProfileDraftChanged,
                onSaveProfile = viewModel::saveProfile,
                onToggleDnsDialog = viewModel::toggleDnsDialog,
                onDnsEnabledChange = viewModel::onCustomDnsEnabledChanged,
                onDnsChange = viewModel::onDnsDraftChanged,
                onSaveDns = viewModel::saveDns,
                onOpenRoutingRules = viewModel::openRoutingRules,
                onCloseRoutingRules = viewModel::closeRoutingRules,
                onRoutingAppSearchChange = viewModel::onRoutingAppSearchChanged,
                onToggleProxyRoutingApp = viewModel::toggleProxyRoutingApp,
                onToggleDirectRoutingApp = viewModel::toggleDirectRoutingApp,
                onSelectAllProxyApps = viewModel::selectAllVisibleProxyApps,
                onClearAllProxyApps = viewModel::clearAllVisibleProxyApps,
                onSelectAllDirectApps = viewModel::selectAllVisibleDirectApps,
                onClearAllDirectApps = viewModel::clearAllVisibleDirectApps,
                onRoutingNationalDomainsChange = viewModel::onRoutingNationalDomainsDraftChanged,
                onRoutingDirectDomainsChange = viewModel::onRoutingDirectDomainsDraftChanged,
                onSaveRoutingRules = viewModel::saveRoutingRules,
                onExportRoutingRules = {
                    val document = viewModel.buildRoutingRulesExport()
                    pendingRoutingRulesExport = document.content
                    exportRoutingRulesLauncher.launch(document.fileName)
                },
                onImportRoutingRules = {
                    importRoutingRulesLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
                onToggleVpn = {
                    val prepareIntent = VpnService.prepare(this)
                    if (prepareIntent != null) {
                        vpnPermissionLauncher.launch(prepareIntent)
                    } else {
                        viewModel.toggleVpn()
                    }
                },
                onRefresh = viewModel::refresh,
                onExportDiagnostics = viewModel::exportDiagnostics,
            )
        }
    }

    override fun onResume() {
        super.onResume()
        if (VpnService.prepare(this) == null) {
            viewModel.onVpnPermissionGranted()
        }
    }
}
