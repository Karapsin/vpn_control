package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.AppInstallSessionPhase
import com.kardinal.vpncontrol.model.AppLanguage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AppInstallSessionPresentationTest {
    @Test fun authorizationFailuresAreLocalizedRatherThanRawControlCodes() {
        AppLanguage.entries.filter { it != AppLanguage.SYSTEM }.forEach { language ->
            val strings = AppStrings(language)
            for (code in listOf("INTERACTION_REQUIRED", "PERMISSION_DENIED")) {
                assertNotEquals(code, updateDetailText(code, strings), "$language/$code")
                assertNotEquals(updateDetailText("CANCELLED", strings), updateDetailText(code, strings))
                if (language != AppLanguage.ENGLISH) assertNotEquals(
                    updateDetailText(code, AppStrings(AppLanguage.ENGLISH)), updateDetailText(code, strings), "$language/$code")
            }
            assertNotEquals(updateDetailText("INTERACTION_REQUIRED", strings), updateDetailText("PERMISSION_DENIED", strings))
        }
    }

    @Test fun unknownInstalledAndPendingAreNotAvailabilityOrFailureAliases() {
        assertEquals(UiText.UPDATE_INSTALL_CONFIRMATION, installSessionText(AppInstallSessionPhase.HANDED_OFF))
        assertEquals(UiText.UPDATE_INSTALL_COMPLETED, installSessionText(AppInstallSessionPhase.INSTALLED))
        assertEquals(UiText.UPDATE_INSTALL_UNKNOWN, installSessionText(AppInstallSessionPhase.UNKNOWN))
        assertEquals(UiText.UPDATE_INSTALL_CANCELLED, installSessionText(AppInstallSessionPhase.CANCELLED))
        assertNotEquals(UiText.UPDATE_UP_TO_DATE, installSessionText(AppInstallSessionPhase.INSTALLED))
        assertNotEquals(UiText.UPDATE_FAILED, installSessionText(AppInstallSessionPhase.UNKNOWN))
    }

    @Test fun everyLanguageHasDistinctLocalizedSessionOutcomes() {
        val keys = listOf(UiText.UPDATE_INSTALL_CONFIRMATION, UiText.UPDATE_INSTALL_COMPLETED,
            UiText.UPDATE_INSTALL_UNKNOWN, UiText.UPDATE_INSTALL_CANCELLED)
        AppLanguage.entries.filter { it != AppLanguage.SYSTEM }.forEach { language ->
            val strings = AppStrings(language)
            assertEquals(strings.get(UiText.UPDATE_INSTALL_CANCELLED), updateDetailText("CANCELLED", strings))
            assertEquals(strings.get(UiText.UPDATE_INSTALL_UNKNOWN), updateDetailText("OUTCOME_UNKNOWN", strings))
            val labels = keys.map(strings::get)
            assertTrue(labels.all(String::isNotBlank))
            assertEquals(keys.size, labels.distinct().size)
            if (language != AppLanguage.ENGLISH) keys.forEach { key ->
                assertNotEquals(AppStrings(AppLanguage.ENGLISH).get(key), strings.get(key), "$language/$key")
            }
        }
    }
}
