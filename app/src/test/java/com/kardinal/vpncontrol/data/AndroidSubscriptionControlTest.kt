package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test

class AndroidSubscriptionControlTest {
    private val one = SubscriptionSource("one", "https://one.invalid", "One", listOf("cached"), 12, "old status")
    private val two = SubscriptionSource("two", "https://two.invalid", "Two")
    private val initial = PersistedState(subscriptions = listOf(two, one), activeSubscriptionId = "two")
    private fun args(vararg pairs: Pair<String, String>) = pairs.associate { it.first to ControlValue.Text(it.second) }
    private fun plan(op: ControlOperationId, values: Map<String, ControlValue>, state: PersistedState = initial) =
        AndroidSubscriptionControl.plan(state, op, values, { value -> runCatching { require(value.startsWith("https://")) } }, { "new-id" })

    @Test fun addPreservesExistingIdentityCacheAndNameWhileMovingAndActivatingIt() {
        val added = plan(ControlOperationId.SUBSCRIPTIONS_ADD, args("input" to " https://one.invalid \n", "name" to " "))
        assertEquals(listOf(one, two), added.subscriptions)
        assertEquals("one", added.targetId); assertEquals("one", added.activeId)
        assertEquals(ProfileSourceMode.SUBSCRIPTION, added.mode)
        val fresh = plan(ControlOperationId.SUBSCRIPTIONS_ADD, args("source" to "https://new.invalid", "name" to "x".repeat(90)))
        assertEquals("new-id", fresh.targetId)
        assertEquals(80, fresh.subscriptions.first().customName.length)
        assertTrue(fresh.subscriptions.first().cachedLocations.isEmpty())
    }

    @Test fun updatesPreserveIdentityOrderAndOnlyUrlChangesInvalidateCache() {
        val renamed = plan(ControlOperationId.SUBSCRIPTIONS_UPDATE, args("id" to "one", "name" to ""))
        assertEquals(one.copy(customName = ""), renamed.subscriptions.last())
        val changed = plan(ControlOperationId.SUBSCRIPTIONS_UPDATE, args("id" to "one", "source" to "https://new.invalid"),
            initial.copy(selectedProfileSourceUrl = one.url))
        assertEquals(listOf("two", "one"), changed.subscriptions.map { it.id })
        assertEquals(one.copy(url = "https://new.invalid", cachedLocations = emptyList(), lastRefreshedAtEpochMillis = 0, lastRefreshStatus = ""), changed.subscriptions.last())
        assertTrue(changed.invalidatesSelectedSource)
        assertEquals("INVALID_ARGUMENT", runCatching { plan(ControlOperationId.SUBSCRIPTIONS_UPDATE, args("id" to "one", "source" to two.url)) }.exceptionOrNull()?.message)
        assertEquals("NOT_FOUND", runCatching { plan(ControlOperationId.SUBSCRIPTIONS_UPDATE, args("id" to "1", "name" to "wrong")) }.exceptionOrNull()?.message)
    }

    @Test fun deleteUsesExactIdAndCollapsesAllToRemainingSourceWithoutSelectingLocation() {
        val deleted = plan(ControlOperationId.SUBSCRIPTIONS_DELETE, args("id" to "two"), initial.copy(activeSubscriptionId = ALL_SUBSCRIPTIONS_ID))
        assertEquals("two", deleted.targetId); assertEquals("one", deleted.activeId)
        assertEquals(listOf(one), deleted.subscriptions)
        assertEquals("NOT_FOUND", runCatching { plan(ControlOperationId.SUBSCRIPTIONS_DELETE, args("id" to "gone")) }.exceptionOrNull()?.message)
        val last = plan(ControlOperationId.SUBSCRIPTIONS_DELETE, args("id" to "one"), initial.copy(subscriptions = listOf(one), activeSubscriptionId = "one"))
        assertEquals("", last.activeId)
    }

    @Test fun legacyGuiUrlChangeNeverInvalidatesRunningOrUnknownSelection() {
        for (running in listOf(true, null)) assertFalse(AndroidSubscriptionControl.renamedSelectionNeedsInvalidation(true, one.url, one.url, running))
        assertTrue(AndroidSubscriptionControl.renamedSelectionNeedsInvalidation(true, one.url, one.url, false))
        assertFalse(AndroidSubscriptionControl.renamedSelectionNeedsInvalidation(false, one.url, one.url, false))
        assertFalse(AndroidSubscriptionControl.renamedSelectionNeedsInvalidation(true, two.url, one.url, false))
    }

    @Test fun grammarRejectsMissingConflictingOrNonTextInput() {
        for ((op, values) in listOf(
            ControlOperationId.SUBSCRIPTIONS_ADD to args("name" to "only"),
            ControlOperationId.SUBSCRIPTIONS_ADD to args("source" to one.url, "input" to one.url),
            ControlOperationId.SUBSCRIPTIONS_UPDATE to args("id" to "one"),
            ControlOperationId.SUBSCRIPTIONS_DELETE to args("id" to "one", "name" to "wrong")))
            assertEquals("INVALID_ARGUMENT", runCatching { plan(op, values) }.exceptionOrNull()?.message)
    }
}
