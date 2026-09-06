package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.SubscriptionSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse

class ControlConfigurationIdentityTest {
    @Test
    fun runtimeAndRefreshMeasurementsDoNotChangeConfigurationIdentity() {
        val state = PersistedState(subscriptions = listOf(SubscriptionSource("one", "private-url", cachedLocations = listOf("private-location"))))
        val identity = ControlConfigurationIdentity.of(state)
        assertEquals(identity, ControlConfigurationIdentity.of(state.copy(
            isVpnRunning = true, statusMessage = "new status", successfulStarts = 1,
            sessionStartedAtEpochMillis = 10, locationBenchmarkDetails = mapOf("private-location" to "measured"),
            subscriptions = state.subscriptions.map { it.copy(lastRefreshedAtEpochMillis = 20, lastRefreshStatus = "done") },
        )))
        assertNotEquals(identity, ControlConfigurationIdentity.of(state.copy(appMode = AppMode.PROXY_ONLY)))
        assertNotEquals(identity, ControlConfigurationIdentity.of(state.copy(
            subscriptions = state.subscriptions.map { it.copy(cachedLocations = listOf("changed")) })))
        assertNotEquals(identity, ControlConfigurationIdentity.of(state.copy(selectedProfileRawLink = "selected")))
        assertFalse(identity.toString().contains("private"))
    }
}
