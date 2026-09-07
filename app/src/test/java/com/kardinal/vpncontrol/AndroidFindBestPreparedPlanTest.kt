package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.ProfileSelectionAttemptPlan
import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test

class AndroidFindBestPreparedPlanTest {
    @Test fun fetchedRowsStayPrivateUntilWinnerTransactionAndPreserveOtherSources() {
        val old = "socks://127.0.0.1:1080#old"
        val winner = "socks://127.0.0.1:1081#winner"
        val source = SubscriptionSource("a", "https://a.test", cachedLocations = listOf(old))
        val untouched = SubscriptionSource("b", "https://b.test", cachedLocations = listOf(old))
        val state = PersistedState(subscriptions = listOf(source, untouched))
        val prepared = AndroidFindBestPlan(ProfileSelectionAttemptPlan(emptyList(), emptyMap(), null), mapOf("a" to listOf(winner)))
        val committed = prepared.subscriptions(state)
        assertEquals(listOf(old), state.subscriptions.first().cachedLocations)
        assertEquals(listOf(winner), committed.first().cachedLocations)
        assertEquals(untouched, committed.last())
        assertTrue(runCatching { prepared.subscriptions(state.copy(subscriptions = listOf(untouched))) }.isFailure)
    }
}
