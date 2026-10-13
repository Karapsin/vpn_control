@file:OptIn(androidx.compose.ui.test.ExperimentalTestApi::class)

package com.kardinal.vpncontrol.desktop

import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.runDesktopComposeUiTest
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.shared.ui.AppStrings
import com.kardinal.vpncontrol.shared.ui.UiText
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import java.nio.file.Files
import org.junit.Test

/** Exercises the actual subscription row through the owner and full desktop frontend. */
class DesktopProfileRefreshStatusTest {
    @Test
    fun legacyRefreshWithTimestampRendersUnavailable() = assertRefreshRow(
        storedStatus = "Updated 1 location",
        expectedStatus = "Refresh status unavailable",
    )

    @Test
    fun legacyRefreshWithoutTimestampStillRendersUnavailable() = assertRefreshRow(
        storedStatus = "Validation warning",
        refreshedAt = 0,
        expectedStatus = "Refresh status unavailable",
    )

    @Test
    fun privateLegacyRefreshTextIsNeverRendered() = assertRefreshRow(
        storedStatus = "Refresh failed for https://private.invalid/sub?token=private-fixture-token",
        expectedStatus = "Refresh status unavailable",
    )

    @Test
    fun unavailableRefreshUsesGermanCatalog() = assertRefreshRow(
        storedStatus = "Updated 1 location",
        language = AppLanguage.GERMAN,
        expectedStatus = "Aktualisierungsstatus nicht verfügbar",
    )

    @Test
    fun unavailableRefreshUsesArabicCatalog() = assertRefreshRow(
        storedStatus = "Updated 1 location",
        language = AppLanguage.ARABIC,
        expectedStatus = "حالة التحديث غير متاحة",
    )

    @Test
    fun trulyEmptyRefreshKeepsNeverRefreshedLabel() = assertRefreshRow(
        storedStatus = "",
        refreshedAt = 0,
        expectedStatus = AppStrings(AppLanguage.ENGLISH).get(UiText.NOT_REFRESHED_YET),
        neverRefreshed = true,
    )

    @Test
    fun typedRefreshSuccessKeepsLocalizedResult() {
        val status = SubscriptionStatusMessages.locationsRefreshed(1)
        assertRefreshRow(status, AppStrings(AppLanguage.GERMAN).statusMessage(status), AppLanguage.GERMAN)
    }

    @Test
    fun typedRefreshFailureKeepsLocalizedResult() {
        val status = SubscriptionStatusMessages.failedToRefreshSubscriptions()
        assertRefreshRow(status, AppStrings(AppLanguage.ENGLISH).statusMessage(status))
    }

    private fun assertRefreshRow(
        storedStatus: String,
        expectedStatus: String,
        language: AppLanguage = AppLanguage.ENGLISH,
        refreshedAt: Long = 1_700_000_000_000L,
        neverRefreshed: Boolean = false,
    ) {
        val directory = Files.createTempDirectory("vpn-control-profile-refresh-status")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            service.replaceStateForVisualCapture(
                MainUiState(
                    currentScreen = AppScreen.PROFILE,
                    appLanguage = language,
                    subscriptions = listOf(SubscriptionSource(
                        id = "public-refresh-fixture",
                        url = "https://example.invalid/subscription",
                        customName = "Public refresh fixture",
                        lastRefreshedAtEpochMillis = refreshedAt,
                        lastRefreshStatus = storedStatus,
                    )),
                    activeSubscriptionId = "public-refresh-fixture",
                ),
                emptyList(),
            )
            runDesktopComposeUiTest(width = 1280, height = 800) {
                setContent {
                    VpnControlTheme {
                        DesktopVpnControlApp(
                            windowProvider = { error("Native dialogs are not used by refresh-status tests") },
                            service = service,
                            onCheckAndDownloadUpdate = {},
                            onDismissOrCancelUpdate = {},
                            onInstallUpdate = {},
                        )
                    }
                }
                waitForIdle()
                val row = onNodeWithTag("profile-current-source")
                row.assertTextContains(expectedStatus, substring = true)
                if (!neverRefreshed) {
                    row.assert(hasText(AppStrings(language).get(UiText.NOT_REFRESHED_YET), substring = true).not())
                }
                if (storedStatus.isNotEmpty()) {
                    row.assert(hasText(storedStatus, substring = true).not())
                }
                row.assert(hasText("private-fixture-token", substring = true).not())
            }
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
