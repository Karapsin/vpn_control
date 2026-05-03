package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.SubscriptionRefreshFailure
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SubscriptionRefreshResultLogicTest {
    @Test
    fun manualSummaryUsesScopeSpecificSuccessMessages() {
        assertEquals(
            SubscriptionStatusMessages.activeSubscriptionRefreshed(),
            SubscriptionRefreshResultLogic.manualSummary(
                scope = SubscriptionRefreshScope.ACTIVE,
                refreshedCount = 1,
                failedSubscriptionNames = emptyList(),
                totalCount = 1,
            ),
        )
        assertEquals(
            SubscriptionStatusMessages.allSubscriptionsRefreshed(),
            SubscriptionRefreshResultLogic.manualSummary(
                scope = SubscriptionRefreshScope.ALL,
                refreshedCount = 2,
                failedSubscriptionNames = emptyList(),
                totalCount = 2,
            ),
        )
    }

    @Test
    fun summaryTruncatesLongFailureLists() {
        assertEquals(
            SubscriptionStatusMessages.subscriptionsRefreshedPartial(2, 5, "A, B +1 more"),
            SubscriptionRefreshResultLogic.summary(
                refreshedCount = 2,
                failedSubscriptionNames = listOf("A", "B", "C", "A"),
                totalCount = 5,
                defaultSuccess = SubscriptionStatusMessages.subscriptionsRefreshed(),
            ),
        )
    }

    @Test
    fun selectedSourceFailedMatchesFailedSourceUrl() {
        assertTrue(
            SubscriptionRefreshResultLogic.selectedSourceFailed(
                selectedProfileSourceUrl = "https://example.com/a",
                failures = listOf(failure(sourceUrl = "https://example.com/a")),
            ),
        )
        assertFalse(
            SubscriptionRefreshResultLogic.selectedSourceFailed(
                selectedProfileSourceUrl = "https://example.com/a",
                failures = listOf(failure(sourceUrl = "https://example.com/b")),
            ),
        )
    }

    @Test
    fun selectedMissingAfterAllRefreshUsesRefreshedCurrentLocations() {
        assertTrue(
            SubscriptionRefreshResultLogic.selectedMissingAfterRefresh(
                refreshAll = true,
                previousState = PersistedState(selectedProfileRawLink = "vless://old"),
                refreshedState = PersistedState(currentLocations = listOf("vless://new")),
                previousSelectedStored = "vless://old",
            ),
        )
        assertFalse(
            SubscriptionRefreshResultLogic.selectedMissingAfterRefresh(
                refreshAll = true,
                previousState = PersistedState(selectedProfileRawLink = "vless://old"),
                refreshedState = PersistedState(currentLocations = listOf("vless://old")),
                previousSelectedStored = "vless://old",
            ),
        )
    }

    @Test
    fun selectedMissingAfterActiveRefreshUsesActiveSubscriptionCache() {
        val previous = PersistedState(
            profileUrl = "https://example.com/sub",
            selectedProfileSourceUrl = "https://example.com/sub",
        )
        val refreshed = PersistedState(
            activeSubscriptionId = "sub",
            subscriptions = listOf(
                SubscriptionSource(
                    id = "sub",
                    url = "https://example.com/sub",
                    cachedLocations = listOf("vless://new"),
                ),
            ),
        )

        assertTrue(
            SubscriptionRefreshResultLogic.selectedMissingAfterRefresh(
                refreshAll = false,
                previousState = previous,
                refreshedState = refreshed,
                previousSelectedStored = "vless://old",
            ),
        )
    }

    @Test
    fun backgroundMessagesPreserveExistingWording() {
        assertEquals(
            SubscriptionStatusMessages.backgroundRefreshSwitched(
                appMode = AppMode.VPN,
                selectedProfileName = "Germany",
                winnerSource = "Main",
                failedLabel = "A",
            ),
            SubscriptionRefreshResultLogic.backgroundSwitchedMessage(
                appMode = AppMode.VPN,
                selectedProfileName = "Germany",
                winnerSource = "Main",
                failedSubscriptionNames = listOf("A"),
            ),
        )
        assertEquals(
            SubscriptionStatusMessages.backgroundRefreshKeptCurrent(
                appMode = AppMode.PROXY_ONLY,
                failedLabel = "A, B +1 more",
                selectedSourceFailed = true,
            ),
            SubscriptionRefreshResultLogic.backgroundKeptCurrentMessage(
                appMode = AppMode.PROXY_ONLY,
                failedSubscriptionNames = listOf("A", "B", "C"),
                selectedSourceFailed = true,
            ),
        )
    }

    private fun failure(sourceUrl: String): SubscriptionRefreshFailure {
        return SubscriptionRefreshFailure(
            subscriptionId = "id",
            sourceUrl = sourceUrl,
            displayName = "Display",
            message = "failed",
        )
    }
}
