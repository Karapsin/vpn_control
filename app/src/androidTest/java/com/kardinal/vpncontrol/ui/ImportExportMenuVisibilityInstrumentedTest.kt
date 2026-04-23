package com.kardinal.vpncontrol.ui

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.model.ProfileSourceMode
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ImportExportMenuVisibilityInstrumentedTest : ImportExportUiTestBase() {
    @Test
    fun profileEditorImportMenuShowsQrClipboardAndFile() {
        runOnUiThread {
            viewModel.openProfileTab()
            if (!viewModel.uiState.value.showAddSubscriptionEditor) {
                viewModel.toggleAddSubscriptionEditor()
            }
        }

        waitForText("Add a new subscription")
        assertTextExists("Import")
        clickText("Import")

        assertTextExists("QR")
        assertTextExists("Clipboard")
        assertTextExists("File")
    }

    @Test
    fun locationsTabShowsOnlyExportInSubscriptionMode() {
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.SUBSCRIPTION)
            viewModel.openLocationsTab()
        }

        waitForText("Locations")
        assertTextExists("Export")
        assertTextDoesNotExist("Import")
    }

    @Test
    fun addLocationDialogImportMenuShowsQrClipboardAndFileInSavedMode() {
        runOnUiThread {
            viewModel.setProfileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS)
            viewModel.openLocationsTab()
            viewModel.showAddLocationDialog()
        }

        waitForText("Add Location")
        assertTextExists("Import")
        clickText("Import")

        assertTextExists("QR")
        assertTextExists("Clipboard")
        assertTextExists("File")
    }

    @Test
    fun rulesScreenImportMenuShowsQrClipboardAndFile() {
        runOnUiThread {
            viewModel.openRoutingRules()
        }

        waitForText("Save Rules")
        assertTextExists("Import")
        clickText("Import")
        assertTextExists("QR")
        assertTextExists("Clipboard")
        assertTextExists("File")
    }

    @Test
    fun rulesScreenExportMenuShowsQrClipboardAndFile() {
        runOnUiThread {
            viewModel.openRoutingRules()
        }

        waitForText("Save Rules")
        assertTextExists("Export")
        clickText("Export")
        assertTextExists("QR")
        assertTextExists("Clipboard")
        assertTextExists("File")
    }
}
