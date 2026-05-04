package com.kardinal.vpncontrol.ui

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.shared.ui.AppStrings
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class StatusMessageRendererInstrumentedTest {
    @Test
    fun structuredStatusRendererRendersPlaceholdersOnAndroid() {
        val message = SettingsStatusMessages.validationSettingsSaved(
            BenchmarkValidationSettings(
                primaryUrl = "https://primary.example/check",
                secondaryUrl = "https://secondary.example/path",
                batchSize = 4,
                subscriptionRefreshConcurrency = 2,
                retryCount = 3,
            ),
        )

        val rendered = AppStrings(AppLanguage.ENGLISH).statusMessage(message)

        assertTrue(rendered.startsWith("Validation settings saved: primary.example"))
        assertTrue(rendered.contains("secondary.example"))
        assertTrue(rendered.contains("batch 4"))
        assertTrue(rendered.contains("refresh 2"))
        assertTrue(rendered.endsWith("retries 3"))
        assertFalse(rendered.contains("{"))
        assertFalse(rendered.contains("}"))
    }
}
