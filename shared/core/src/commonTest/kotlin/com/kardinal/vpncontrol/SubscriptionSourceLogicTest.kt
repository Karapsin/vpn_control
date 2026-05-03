package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SubscriptionSourceLogicTest {
    @Test
    fun activateAllKeepsProfileUrlAndUsesSubscriptionMode() {
        val state = MainUiState(
            profileUrl = "https://example.com/active",
            activeSubscriptionId = "sub",
            subscriptions = listOf(subscription("sub", "https://example.com/active")),
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
        )

        val plan = SubscriptionSourceLogic.activateSubscription(state, ALL_SUBSCRIPTIONS_ID)!!

        assertEquals(ALL_SUBSCRIPTIONS_ID, plan.nextState.activeSubscriptionId)
        assertEquals("https://example.com/active", plan.nextState.profileUrl)
        assertEquals(ProfileSourceMode.SUBSCRIPTION, plan.nextState.profileSourceMode)
        assertEquals(SubscriptionStatusMessages.activatedAllSubscriptions(), plan.statusMessage)
    }

    @Test
    fun saveSubscriptionDraftMovesExistingSourceToFront() {
        val first = subscription("one", "https://example.com/one")
        val second = subscription("two", "https://example.com/two", customName = "Two")
        val state = MainUiState(
            subscriptions = listOf(first, second),
            profileDraft = " https://example.com/two ",
        )

        val plan = SubscriptionSourceLogic.saveSubscriptionDraft(
            state = state,
            validateSubscription = { Result.success(Unit) },
            idGenerator = { "new" },
        ).getOrThrow()

        assertEquals(listOf("two", "one"), plan.nextState.subscriptions.map(SubscriptionSource::id))
        assertEquals("two", plan.nextState.activeSubscriptionId)
        assertEquals("https://example.com/two", plan.nextState.profileUrl)
        assertFalse(plan.nextState.showAddSubscriptionEditor)
    }

    @Test
    fun saveSubscriptionDraftUsesOptionalTitle() {
        val state = MainUiState(
            profileDraft = " https://example.com/new ",
            profileTitleDraft = "VLESS (auto)",
        )

        val plan = SubscriptionSourceLogic.saveSubscriptionDraft(
            state = state,
            validateSubscription = { Result.success(Unit) },
            idGenerator = { "new" },
        ).getOrThrow()

        assertEquals("VLESS (auto)", plan.nextState.subscriptions.single().customName)
        assertEquals("", plan.nextState.profileTitleDraft)
    }

    @Test
    fun saveRenameCanChangeSubscriptionUrlAndTitle() {
        val state = MainUiState(
            activeSubscriptionId = "one",
            profileUrl = "https://example.com/one",
            profileDraft = "https://example.com/one",
            subscriptions = listOf(
                SubscriptionSource(
                    id = "one",
                    url = "https://example.com/one",
                    customName = "Old",
                    cachedLocations = listOf("old-location"),
                    lastRefreshedAtEpochMillis = 42L,
                    lastRefreshStatus = "fresh",
                ),
            ),
            selectedProfileName = "Selected",
            selectedProfileSourceUrl = "https://example.com/one",
            profileHistoryRenameSource = "https://example.com/one",
            profileHistoryRenameUrlDraft = " https://example.com/two ",
            profileHistoryRenameDraft = "Two",
        )

        val plan = SubscriptionSourceLogic.saveRename(
            state = state,
            validateSubscription = { Result.success(Unit) },
        ).getOrThrow()

        val updated = plan.nextState.subscriptions.single()
        assertEquals("https://example.com/one", plan.source)
        assertEquals("https://example.com/two", plan.normalizedSource)
        assertEquals("Two", updated.customName)
        assertEquals("https://example.com/two", updated.url)
        assertEquals(emptyList(), updated.cachedLocations)
        assertEquals("https://example.com/two", plan.nextState.profileUrl)
        assertEquals("https://example.com/two", plan.nextState.profileDraft)
        assertEquals("", plan.nextState.selectedProfileSourceUrl)
        assertFalse(plan.nextState.showProfileHistoryRenameDialog)
    }

    @Test
    fun deleteSubscriptionClearsSelectionOnlyWhenRemovedSourceWasSelected() {
        val first = subscription("one", "https://example.com/one")
        val second = subscription("two", "https://example.com/two")
        val state = MainUiState(
            activeSubscriptionId = "one",
            subscriptions = listOf(first, second),
            selectedProfileName = "Selected",
            selectedProfileServer = "127.0.0.1",
            selectedProfileRawLink = "selected-raw",
            selectedProfileSourceUrl = first.url,
        )

        val plan = SubscriptionSourceLogic.deleteSubscription(
            state = state,
            subscriptionId = first.id,
            selectedRawPresentAfterDelete = true,
        )!!

        assertEquals(first, plan.target)
        assertTrue(plan.removedSelected)
        assertEquals(listOf("two"), plan.nextState.subscriptions.map(SubscriptionSource::id))
        assertEquals("two", plan.nextState.activeSubscriptionId)
        assertEquals(second.url, plan.nextState.profileUrl)
        assertEquals("", plan.nextState.selectedProfileRawLink)
        assertEquals(SubscriptionStatusMessages.subscriptionDeleted(), plan.statusMessage)
    }

    @Test
    fun deleteSubscriptionKeepsAllGroupWhenMultipleSubscriptionsRemain() {
        val state = MainUiState(
            activeSubscriptionId = ALL_SUBSCRIPTIONS_ID,
            subscriptions = listOf(
                subscription("one", "https://example.com/one"),
                subscription("two", "https://example.com/two"),
                subscription("three", "https://example.com/three"),
            ),
        )

        val plan = SubscriptionSourceLogic.deleteSubscription(
            state = state,
            subscriptionId = "one",
            selectedRawPresentAfterDelete = true,
        )!!

        assertEquals(ALL_SUBSCRIPTIONS_ID, plan.nextState.activeSubscriptionId)
        assertEquals("", plan.nextState.profileUrl)
        assertFalse(plan.removedSelected)
    }

    private fun subscription(
        id: String,
        url: String,
        customName: String = "",
    ): SubscriptionSource {
        return SubscriptionSource(
            id = id,
            url = url,
            customName = customName,
        )
    }
}
