package com.kardinal.vpncontrol.ui

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.MainActivityTestBridge
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.model.ProfileSourceMode
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ImportExportErrorInstrumentedTest : ImportExportUiTestBase() {
    @Test
    fun emptyClipboardImportShowsStatusMessage() {
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
            MainActivityTestBridge.setClipboardOverride("   ")
            MainActivityTestBridge.invokeImportFromClipboard(composeRule.activity, ImportPreference.LOCATION)
        }

        waitUntil { hasLoggedMessage("Clipboard is empty") }
        assertTrue(hasLoggedMessage("Clipboard is empty"))
    }

    @Test
    fun blankQrImportShowsCanceledStatus() {
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
            MainActivityTestBridge.invokeLocationQrImport(composeRule.activity, "   ")
        }

        waitUntil { hasLoggedMessage("QR scan canceled") }
        assertTrue(hasLoggedMessage("QR scan canceled"))
    }

    @Test
    fun emptyLocationsFileImportShowsError() {
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.importLocations("   ")
        }

        waitUntil { hasLoggedMessage("Locations import is empty") }
        assertTrue(hasLoggedMessage("Locations import is empty"))
    }

    @Test
    fun invalidRulesFileImportShowsError() {
        runOnUiThread {
            viewModel.openRoutingRules()
            viewModel.importRoutingRules("""{"unexpected":true}""")
        }

        waitUntil { hasLoggedMessage("Routing rules JSON format is not recognized") }
        assertTrue(hasLoggedMessage("Routing rules JSON format is not recognized"))
    }

    private fun hasLoggedMessage(message: String): Boolean {
        return viewModel.uiState.value.connectionLog.any { it.message == message }
    }
}
