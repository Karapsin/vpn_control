package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test

class AndroidConnectionPresentationTest {
    private val actual = "socks://127.0.0.1:1080#Actual%20A"
    private val pending = "socks://127.0.0.1:1081#Pending%20B"
    private fun state(location: String) = PersistedState(selectedProfileRawLink = location, currentLocations = listOf(location))
    private fun prepared(state: PersistedState) = ControlRuntimeConfiguration.committed(MainUiStateProjector.committedState(state))

    @Test fun runningNameComesFromCapturedLocationAfterSelectionAndCachedLocationRemoval() {
        val observer = AndroidRuntimeObserver()
        val original = state(actual)
        val handle = Any()
        observer.started(handle, AppMode.VPN, "actual-runtime", prepared(original))
        val first = requireNotNull(observer.locationVisualState(original).connectionConfiguration)
        assertEquals(true, first.runtimeRunning)
        assertEquals("Actual A", first.activeLocationName)
        assertEquals(false, first.restartRequired)

        val replacement = state(pending)
        val afterSelection = observer.locationVisualState(replacement)
        val presentation = requireNotNull(afterSelection.connectionConfiguration)
        assertEquals("Actual A", presentation.activeLocationName)
        assertEquals(true, presentation.restartRequired)
        assertEquals(androidLocationVisualKey(actual, ""), afterSelection.activeLocationKey)
        // Duplicate native notifications cannot replace the captured actual identity.
        observer.started(handle, AppMode.VPN, "ignored-runtime", prepared(replacement))
        assertEquals(presentation, observer.locationVisualState(replacement).connectionConfiguration)

        observer.resetCompleted(true)
        observer.started(Any(), AppMode.VPN, "new-runtime", prepared(replacement))
        assertEquals("Pending B", observer.locationVisualState(replacement).connectionConfiguration?.activeLocationName)
        assertEquals(false, observer.locationVisualState(replacement).connectionConfiguration?.restartRequired)
    }

    @Test fun unknownRuntimeAndUncapturedRunningRuntimeRemainExplicitlyUnknown() {
        val observer = AndroidRuntimeObserver()
        val committed = state(pending).copy(isVpnRunning = true)
        val unknown = requireNotNull(observer.locationVisualState(committed).connectionConfiguration)
        assertNull(unknown.runtimeRunning)
        assertNull(unknown.activeLocationName)
        assertNull(unknown.restartRequired)

        observer.started(Any(), AppMode.VPN, "runtime-without-captured-inputs")
        val unmatched = requireNotNull(observer.locationVisualState(committed).connectionConfiguration)
        assertEquals(true, unmatched.runtimeRunning)
        assertNull(unmatched.activeLocationName)
        assertNull(unmatched.restartRequired)
        observer.resetCompleted(false)
        assertNull(observer.locationVisualState(committed).connectionConfiguration?.runtimeRunning)
    }

    @Test fun provenOffClearsDisplayIdentityAndIgnoresPersistedRunningFlag() {
        val observer = AndroidRuntimeObserver()
        val committed = state(actual).copy(isVpnRunning = true)
        observer.started(Any(), AppMode.VPN, "actual-runtime", prepared(committed))
        observer.resetCompleted(true)
        val visual = observer.locationVisualState(committed)
        val presentation = requireNotNull(visual.connectionConfiguration)
        assertEquals(false, presentation.runtimeRunning)
        assertNull(presentation.activeLocationName)
        assertEquals(false, presentation.restartRequired)
        assertNull(visual.activeLocationKey)
    }

    @Test fun unreadableCapturedLocationDoesNotFallBackToSelectedNameOrExposeRuntimeInputs() {
        val observer = AndroidRuntimeObserver()
        observer.started(Any(), AppMode.VPN, "private-runtime", prepared(state("unparseable://private-input")))
        val presentation = requireNotNull(observer.locationVisualState(state(pending)).connectionConfiguration)
        assertEquals(true, presentation.runtimeRunning)
        assertNull(presentation.activeLocationName)
        assertEquals(true, presentation.restartRequired)
        assertFalse(presentation.toString().contains("private"))
    }
}
