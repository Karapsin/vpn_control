package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopSourcePresentationTest {
    @Test fun sourceReferencesAndMismatchDoNotExposePrivateUrls() {
        val first = SubscriptionSource("first", "https://USER:PRIVATE_PASSWORD@first.example/SUBSCRIPTION_TOKEN", customName = "Office")
        val second = SubscriptionSource("second", "https://second.example/OTHER_TOKEN")
        val state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = first.id, profileUrl = first.url, subscriptions = listOf(first, second),
            selectedProfileName = "Pending selection", selectedProfileSourceUrl = second.url)
        val value = DesktopSourcePresentation.capture(state)
        assertEquals("first", value.current.subscriptionId)
        assertEquals("Office", value.current.displayName)
        assertEquals("second", value.selected.subscriptionId)
        assertEquals("second.example", value.selected.displayName)
        assertTrue(value.selectedOutsideCurrent)
        val encoded = ControlProtocolCodec.encodeValues(value.values())
        listOf("USER", "PRIVATE_PASSWORD", "SUBSCRIPTION_TOKEN", "OTHER_TOKEN", "https://").forEach {
            assertFalse(encoded.contains(it))
        }
        assertEquals(value, DesktopSourcePresentation.fromValues(value.values()))
        val merged = DesktopSourcePresentation.capture(state.copy(activeSubscriptionId = ALL_SUBSCRIPTIONS_ID))
        assertEquals(DesktopSourceLabelKind.ALL_SUBSCRIPTIONS, merged.current.kind)
        assertFalse(merged.selectedOutsideCurrent)
    }

    @Test fun unnamedSourceUsesHostnameOnlyAndMalformedSourcesNeverBecomeDisplayInput() {
        val source = SubscriptionSource("source", "https://user:PRIVATE@host.example/private?token=SECRET")
        val state = MainUiState(profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
            activeSubscriptionId = source.id, subscriptions = listOf(source), profileUrl = source.url)
        assertEquals("host.example", DesktopSourcePresentation.capture(state).current.displayName)
        val malformed = source.copy(url = "not a url PRIVATE_CONTENT")
        val value = DesktopSourcePresentation.capture(state.copy(subscriptions = listOf(malformed), profileUrl = malformed.url))
        assertEquals(DesktopSourceLabelKind.DIFFERENT_SUBSCRIPTION, value.current.kind)
        assertFalse(ControlProtocolCodec.encodeValues(value.values()).contains("PRIVATE_CONTENT"))
    }

    @Test fun localSourceHasNoSubscriptionIdentityAndMalformedWireTypesAreRejected() {
        val value = DesktopSourcePresentation.capture(MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS))
        assertEquals(DesktopSourceLabelKind.SAVED_LOCATIONS, value.current.kind)
        assertFalse(value.selectedOutsideCurrent)
        assertEquals(value, DesktopSourcePresentation.fromValues(value.values()))
        assertFails { DesktopSourcePresentation.fromValues(value.values() + ("selectedOutsideCurrent" to ControlValue.Text("false"))) }
    }
}
