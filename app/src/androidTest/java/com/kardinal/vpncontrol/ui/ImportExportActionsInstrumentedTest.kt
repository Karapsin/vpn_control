package com.kardinal.vpncontrol.ui

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.MainActivityTestBridge
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.ProfileSourceMode
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ImportExportActionsInstrumentedTest : ImportExportUiTestBase() {
    @Test
    fun profileQrImportPopulatesSubscriptionDraft() {
        val payload = "https://example.com/subscription-from-qr"
        runOnUiThread {
            viewModel.openProfileTab()
            if (!viewModel.uiState.value.showAddSubscriptionEditor) {
                viewModel.toggleAddSubscriptionEditor()
            }
            MainActivityTestBridge.invokeSubscriptionQrImport(composeRule.activity, payload)
        }

        waitUntil { viewModel.uiState.value.profileDraft == payload }

        assertTrue(viewModel.uiState.value.showAddSubscriptionEditor)
        assertTrue(viewModel.uiState.value.profileDraft == payload)
    }

    @Test
    fun profileFileImportPopulatesSubscriptionDraft() {
        val payload = "https://example.com/subscription-from-file"
        runOnUiThread {
            viewModel.openProfileTab()
            if (!viewModel.uiState.value.showAddSubscriptionEditor) {
                viewModel.toggleAddSubscriptionEditor()
            }
            MainActivityTestBridge.invokeImportFile(composeRule.activity, ImportPreference.SUBSCRIPTION, payload)
        }

        waitUntil { viewModel.uiState.value.profileDraft == payload }

        assertTrue(viewModel.uiState.value.showAddSubscriptionEditor)
        assertTrue(viewModel.uiState.value.profileDraft == payload)
    }

    @Test
    fun addLocationClipboardImportPopulatesLocationDraft() {
        val payload = "socks://testuser:testpass@127.0.0.1:1080#Clipboard Socks"
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
            MainActivityTestBridge.setClipboardOverride(payload)
        }

        waitForText("Add Location")
        runOnUiThread {
            MainActivityTestBridge.invokeImportFromClipboard(composeRule.activity, ImportPreference.LOCATION)
        }
        waitUntil {
            viewModel.uiState.value.showLocationDialog &&
                viewModel.uiState.value.locationDraft == payload
        }

        assertTrue(viewModel.uiState.value.showLocationDialog)
        assertTrue(viewModel.uiState.value.locationDraft == payload)
    }

    @Test
    fun addLocationQrImportPopulatesLocationDraft() {
        val payload = "socks://testuser:testpass@127.0.0.1:1080#QR Socks"
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
            MainActivityTestBridge.invokeLocationQrImport(composeRule.activity, payload)
        }

        waitUntil {
            viewModel.uiState.value.showLocationDialog &&
                viewModel.uiState.value.locationDraft == payload
        }

        assertTrue(viewModel.uiState.value.showLocationDialog)
        assertTrue(viewModel.uiState.value.locationDraft == payload)
    }

    @Test
    fun addLocationFileImportPopulatesLocationDraft() {
        val payload = "socks://testuser:testpass@127.0.0.1:1080#File Socks"
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
            MainActivityTestBridge.invokeImportFile(composeRule.activity, ImportPreference.LOCATION, payload)
        }

        waitUntil {
            viewModel.uiState.value.showLocationDialog &&
                viewModel.uiState.value.locationDraft == payload
        }

        assertTrue(viewModel.uiState.value.showLocationDialog)
        assertTrue(viewModel.uiState.value.locationDraft == payload)
    }

    @Test
    fun rulesClipboardImportUpdatesDraftState() {
        val payload = """
            {
              "rules": {
                "ignore_rules": true,
                "proxy_packages": ["com.example.app"],
                "national_domain_suffixes": ["ru"],
                "direct_domain_suffixes": ["example.com"]
              }
            }
        """.trimIndent()
        runOnUiThread {
            viewModel.openRoutingRules()
            MainActivityTestBridge.setClipboardOverride(payload)
        }

        waitForText("Save Rules")
        runOnUiThread {
            MainActivityTestBridge.invokeImportFromClipboard(composeRule.activity, ImportPreference.ROUTING_RULES)
        }
        waitUntil {
            val state = viewModel.uiState.value
            state.routingIgnoreRulesDraft &&
                state.routingProxyPackagesDraft.contains("com.example.app") &&
                state.routingNationalDomainsDraft == "ru" &&
                state.routingDirectDomainsDraft == "example.com"
        }

        val state = viewModel.uiState.value
        assertTrue(state.routingIgnoreRulesDraft)
        assertTrue(state.routingProxyPackagesDraft.contains("com.example.app"))
        assertTrue(state.routingNationalDomainsDraft == "ru")
        assertTrue(state.routingDirectDomainsDraft == "example.com")
    }

    @Test
    fun rulesQrImportUpdatesDraftState() {
        val payload = """
            {
              "rules": {
                "ignore_rules": false,
                "proxy_packages": ["com.example.qr"],
                "national_domain_suffixes": ["de"],
                "direct_domain_suffixes": ["qr.example"]
              }
            }
        """.trimIndent()
        runOnUiThread {
            viewModel.openRoutingRules()
            MainActivityTestBridge.invokeRoutingRulesQrImport(composeRule.activity, payload)
        }

        waitUntil {
            val state = viewModel.uiState.value
            !state.routingIgnoreRulesDraft &&
                state.routingProxyPackagesDraft.contains("com.example.qr") &&
                state.routingNationalDomainsDraft == "de" &&
                state.routingDirectDomainsDraft == "qr.example"
        }

        val state = viewModel.uiState.value
        assertTrue(!state.routingIgnoreRulesDraft)
        assertTrue(state.routingProxyPackagesDraft.contains("com.example.qr"))
        assertTrue(state.routingNationalDomainsDraft == "de")
        assertTrue(state.routingDirectDomainsDraft == "qr.example")
    }

    @Test
    fun rulesFileImportUpdatesDraftState() {
        val payload = """
            {
              "rules": {
                "ignore_rules": true,
                "proxy_packages": ["com.example.file"],
                "national_domain_suffixes": ["fr"],
                "direct_domain_suffixes": ["file.example"]
              }
            }
        """.trimIndent()
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.importRoutingRules(payload)
        }

        waitUntil {
            val state = viewModel.uiState.value
            state.routingIgnoreRulesDraft &&
                state.routingProxyPackagesDraft.contains("com.example.file") &&
                state.routingNationalDomainsDraft == "fr" &&
                state.routingDirectDomainsDraft == "file.example"
        }

        val state = viewModel.uiState.value
        assertTrue(state.routingIgnoreRulesDraft)
        assertTrue(state.routingProxyPackagesDraft.contains("com.example.file"))
        assertTrue(state.routingNationalDomainsDraft == "fr")
        assertTrue(state.routingDirectDomainsDraft == "file.example")
    }

    @Test
    fun rulesClipboardExportWritesJsonToClipboard() {
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.onRoutingDirectDomainsDraftChanged("example.com")
        }

        waitForText("Save Rules")
        clickText("Export")
        clickTag("export-menu-clipboard")
        waitUntil {
            readClipboardText().contains("vpn_control_routing_rules")
        }

        assertTrue(readClipboardText().contains("vpn_control_routing_rules"))
        assertTrue(readClipboardText().contains("example.com"))
    }

    @Test
    fun locationsClipboardExportWritesJsonToClipboard() {
        val stored = listOf("socks://export:pass@127.0.0.1:1080#Export Location")
        val payload = LocationConfigs.export(stored).content
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.importLocations(payload)
        }

        waitUntil { viewModel.uiState.value.currentLocations.isNotEmpty() }
        clickText("Export")
        clickTag("export-menu-clipboard")
        waitUntil {
            readClipboardText().contains("vpn_control_locations")
        }

        assertTrue(readClipboardText().contains("vpn_control_locations"))
        assertTrue(readClipboardText().contains("Export Location"))
    }

    @Test
    fun rulesQrExportShowsDialogForSmallPayload() {
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.onRoutingDirectDomainsDraftChanged("small.example")
        }

        waitForText("Save Rules")
        clickText("Export")
        clickTag("export-menu-qr")
        waitForText("Rules Export")
        assertTextExists("Rules Export")
    }

    @Test
    fun rulesQrExportShowsOversizeError() {
        val oversizedDomains = (1..200).joinToString("\n") { index ->
            "very-long-domain-name-number-$index.example.com"
        }
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.onRoutingDirectDomainsDraftChanged(oversizedDomains)
        }

        waitForText("Save Rules")
        clickText("Export")
        clickTag("export-menu-qr")
        waitForText("QR Export Too Large")
        assertTextExists("QR Export Too Large")
    }

    @Test
    fun rulesFileExportContainsExpectedJsonShape() {
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.onRoutingIgnoreRulesDraftChanged(true)
            viewModel.onRoutingDirectDomainsDraftChanged("file-export.example")
        }

        val document = viewModel.buildRoutingRulesExport()
        assertTrue(document.content.contains("\"type\": \"vpn_control_routing_rules\""))
        assertTrue(document.content.contains("\"ignore_rules\": true"))
        assertTrue(document.content.contains("file-export.example"))
    }

    @Test
    fun locationsFileExportContainsExpectedJsonShape() {
        val stored = listOf("socks://shape:pass@127.0.0.1:1080#Shape Location")
        val payload = LocationConfigs.export(stored).content
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.importLocations(payload)
        }

        waitUntil { viewModel.uiState.value.currentLocations.isNotEmpty() }
        val document = viewModel.buildLocationsExport()
        assertTrue(document.content.contains("\"type\": \"vpn_control_locations\""))
        assertTrue(document.content.contains("\"locations\""))
        assertTrue(document.content.contains("Shape Location"))
    }
}
