package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test

class AndroidPreparedConnectionsTest {
    @Test fun delayedServiceStartUsesPreparedInputsNotLaterCommittedSettings() {
        val prepared = AndroidPreparedConnections()
        val selection = selection()
        val original = PersistedState(selectedProfileRawLink = selection.profile.rawLink, appMode = AppMode.PROXY_ONLY)
        val configuration = ControlRuntimeConfiguration.committed(MainUiStateProjector.mergePersistedState(MainUiState(), original))
        prepared.remember(selection, configuration)
        val token = prepared.dispatch(selection)
        val later = original.copy(dnsSettings = original.dnsSettings.copy(mode = DnsMode.CUSTOM_DOH, endpoint = "https://dns.example/dns-query"))
        val observed = AndroidRuntimeObserver()
        val descriptor = prepared.consume(token, selection.runtimeConfigJson)
        assertEquals(configuration, descriptor)
        val handle = Any()
        observed.started(handle, AppMode.PROXY_ONLY, selection.runtimeConfigJson, descriptor)
        val runtimeId = observed.state.value.runtimeId
        assertEquals(false, observed.pendingRestart(original))
        assertEquals(true, observed.pendingRestart(later))
        assertEquals(false, observed.pendingRestart(original))
        observed.started(handle, AppMode.PROXY_ONLY, selection.runtimeConfigJson, descriptor)
        assertEquals(runtimeId, observed.state.value.runtimeId)
        assertEquals(true, observed.pendingRestart(later))
        observed.resetCompleted(true)
        assertEquals(false, observed.pendingRestart(later))
    }

    @Test fun staleCopiedOrMismatchedHandoffsNeverReconstructActiveConfigurationFromFile() {
        var now = 0L
        val prepared = AndroidPreparedConnections(clockMillis = { now }, retentionMillis = 10)
        val selection = selection()
        val configuration = ControlRuntimeConfiguration.committed(MainUiState(selectedProfileRawLink = selection.profile.rawLink))
        prepared.remember(selection, configuration)
        assertNull(prepared.dispatch(selection.copy()))
        val token = prepared.dispatch(selection)
        assertNull(prepared.consume(token, "different-config"))
        assertNull(prepared.consume(token, selection.runtimeConfigJson))
        val expiring = prepared.dispatch(selection)
        now = 10
        assertNull(prepared.consume(expiring, selection.runtimeConfigJson))
        assertNull(prepared.consume(null, selection.runtimeConfigJson))
        assertNull(prepared.consume("arbitrary-file-name", selection.runtimeConfigJson))
    }

    @Test fun unknownStickyStartModeMismatchAndFailedStartCleanupStayTruthful() {
        val observer = AndroidRuntimeObserver()
        val state = PersistedState()
        assertNull(observer.pendingRestart(state))
        observer.started(Any(), AppMode.PROXY_ONLY, "sticky-file-without-handoff")
        assertNull(observer.pendingRestart(state))
        val configuration = ControlRuntimeConfiguration.committed(MainUiState(appMode = AppMode.VPN))
        observer.started(Any(), AppMode.PROXY_ONLY, "actual-proxy-config", configuration)
        assertNull(observer.pendingRestart(state))
        observer.resetCompleted(true)
        assertEquals(false, observer.pendingRestart(state))
        val prepared = AndroidPreparedConnections()
        val selection = selection()
        prepared.remember(selection, configuration)
        val token = prepared.dispatch(selection)
        prepared.discard(token)
        assertNull(prepared.consume(token, selection.runtimeConfigJson))
    }

    private fun selection(): ProfileSelection {
        val profile = LocationConfigs.parseLocationInput("socks://127.0.0.1:1080#Fixture")
        return ProfileSelection(profile, ProfileBenchmark(profile, "cached", "cached", null, null, 0.0, "fixture"), "private-runtime-config")
    }
}
